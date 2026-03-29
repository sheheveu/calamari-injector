#pragma once

namespace driver {
	namespace memory {
		__forceinline uintptr_t to_addr( const void* pointer ) {
			return reinterpret_cast< uintptr_t >( pointer );
		}

		__forceinline void* to_ptr( uintptr_t address ) {
			return reinterpret_cast< void* >( address );
		}

		__forceinline bool is_valid( uintptr_t address ) {
			return ( address >= 0x0000000000010000 && address < 0x00007FFFFFFEFFFF );
		}

		__forceinline bool is_valid( const void* pointer ) {
			return is_valid( to_addr( pointer ) );
		}
	}

	class c_driver {
	private:
		control::control_data_t* m_control_data{};
		std::uint8_t* m_shared_buffer{};
		HKEY m_registry_key{};
		HANDLE m_response_semaphore{};
		HANDLE m_request_event{};
		SRWLOCK m_request_lock{};

		std::unordered_map<std::uint64_t, pml4e> m_cache_pml4e;
		std::unordered_map<std::uint64_t, pdpte> m_cache_pdpte;
		std::unordered_map<std::uint64_t, pde> m_cache_pde;
		std::unordered_map<std::uint64_t, pte> m_cache_pte;
		SRWLOCK m_cache_lock;

		bool send_control( DWORD timeout = 3000 ) {
			AcquireSRWLockExclusive( &m_request_lock );

			_InterlockedExchange( reinterpret_cast< volatile long* >( &m_control_data->m_response_ready ), 0 );
			SetEvent( m_request_event );

			auto start = std::chrono::high_resolution_clock::now( );
			auto timeout_duration = std::chrono::milliseconds( timeout );

			int spin_count = 0;
			while ( _InterlockedCompareExchange(
				reinterpret_cast< volatile long* >( &m_control_data->m_response_ready ),
				0,
				0
			) == 0 ) {
				if ( std::chrono::high_resolution_clock::now( ) - start > timeout_duration ) {
					ReleaseSRWLockExclusive( &m_request_lock );
					logging::print( oxorany( "[calamari] control request timed out.\n" ) );
					return false;
				}

				_mm_pause( );
			}

			ReleaseSRWLockExclusive( &m_request_lock );
			return true;
		}

		bool read_virtual_single( void* dst, std::uint64_t va, std::size_t size ) {
			if ( size > paging::page_4kb_size )
				return false;

			m_control_data->m_request_type = control::control_type::read;
			m_control_data->m_address = va;
			m_control_data->m_size = size;

			if ( !send_control( ) )
				return false;

			if ( m_control_data->m_status ) {
				memcpy( dst, m_shared_buffer, size );
			}

			return m_control_data->m_status;
		}

		bool write_virtual_single( void* src, std::uint64_t va, std::size_t size ) {
			if ( size > paging::page_4kb_size )
				return false;

			memcpy( m_shared_buffer, src, size );

			m_control_data->m_request_type = control::control_type::write_virtual;
			m_control_data->m_address = va;
			m_control_data->m_size = size;

			if ( !send_control( ) )
				return false;

			return m_control_data->m_status;
		}

		bool read_physical_single( void* dst, std::uint64_t pa, std::size_t size ) {
			if ( size > paging::page_4kb_size )
				return false;

			m_control_data->m_request_type = control::control_type::read_physical;
			m_control_data->m_address = pa;
			m_control_data->m_size = size;

			if ( !send_control( ) )
				return false;

			if ( m_control_data->m_status ) {
				memcpy( dst, m_shared_buffer, size );
			}

			return m_control_data->m_status;
		}

		bool write_physical_single( void* src, std::uint64_t pa, std::size_t size ) {
			if ( size > paging::page_4kb_size )
				return false;

			memcpy( m_shared_buffer, src, size );

			m_control_data->m_request_type = control::control_type::write_physical;
			m_control_data->m_address = pa;
			m_control_data->m_size = size;

			if ( !send_control( ) )
				return false;

			return m_control_data->m_status;
		}

		void cleanup( ) {
			if ( m_control_data ) {
				VirtualFree( m_control_data, 0, MEM_RELEASE );
				m_control_data = nullptr;
				m_shared_buffer = nullptr;
			}
			if ( m_response_semaphore ) {
				CloseHandle( m_response_semaphore );
				m_response_semaphore = nullptr;
			}
			if ( m_request_event ) {
				CloseHandle( m_request_event );
				m_request_event = nullptr;
			}
		}

	public:
		c_driver( ) { }
		~c_driver( ) { cleanup( ); }

		std::uint32_t m_process_id{};
		HWND m_process_window{};
		eprocess_t* m_eprocess{};
		peb_t* m_process_peb{};
		std::uint64_t m_base_address{};
		std::uint64_t m_directory_table_base{};

		bool create( ) {
			InitializeSRWLock( &m_request_lock );
			InitializeSRWLock( &m_cache_lock );

			auto result = RegCreateKeyExW(
				HKEY_CURRENT_USER,
				L"SOFTWARE\\{b0a6c5bb-d971-417b-a9af-6b0a69c095d1}",
				0,
				nullptr,
				REG_OPTION_VOLATILE,
				KEY_WRITE | KEY_SET_VALUE,
				nullptr,
				&m_registry_key,
				nullptr
			);

			if ( result != ERROR_SUCCESS )
				return false;

			m_response_semaphore = CreateSemaphoreA( nullptr, 0, LONG_MAX, nullptr );
			if ( !m_response_semaphore )
				return false;

			m_request_event = CreateEventA( nullptr, FALSE, FALSE, nullptr );
			if ( !m_request_event )
				return false;

			return true;
		}

		bool initialize( ) {
			this->m_control_data = reinterpret_cast< control::control_data_t* >(
				VirtualAlloc(
					nullptr,
					sizeof( control::control_data_t ) + paging::page_4kb_size,
					MEM_COMMIT | MEM_RESERVE,
					PAGE_READWRITE
				) );

			if ( !m_control_data )
				return false;

			memset( m_control_data, 0, sizeof( control::control_data_t ) + paging::page_4kb_size );

			this->m_shared_buffer = reinterpret_cast< std::uint8_t* >(
				reinterpret_cast< std::uint8_t* >( m_control_data ) + sizeof( control::control_data_t )
				);

			control::control_initialize_t control_initialize{};
			control_initialize.m_process_id = GetCurrentProcessId( );
			control_initialize.m_base_address = reinterpret_cast< std::uint64_t >( m_control_data );
			control_initialize.m_response_semaphore = m_response_semaphore;
			control_initialize.m_request_event = m_request_event;

			auto result = RegSetValueExW(
				m_registry_key,
				L"{5f86769f-fdfd-4c36-8e9a-e9a92fe7480a}",
				0,
				REG_BINARY,
				reinterpret_cast< const BYTE* >( &control_initialize ),
				sizeof( control_initialize )
			);

			if ( result != ERROR_SUCCESS )
				return false;

			RegCloseKey( m_registry_key );
			RegDeleteKeyW( HKEY_CURRENT_USER, L"SOFTWARE\\{b0a6c5bb-d971-417b-a9af-6b0a69c095d1}" );

			return true;
		}

		bool is_active( ) {
			m_control_data->m_request_type = control::control_type::verify;
			return send_control( );
		}

		void unload( ) {
			if ( !m_control_data ) return;
			m_control_data->m_request_type = control::control_type::unload_driver;
			send_control( );
			cleanup( );
		}

		bool read_virtual_ptm( void* dst, std::uint64_t va, std::size_t size ) {
			auto current_page = va;
			auto current_dst = static_cast< std::uint8_t* >( dst );
			auto remaining = size;

			while ( remaining > 0 ) {
				std::uint32_t page_size = 0;
				auto pa = translate_linear( current_page, &page_size );
				if ( !pa )
					return false;

				auto page_offset = pa & ( page_size - 1 );
				auto bytes_in_page = page_size - page_offset;
				auto to_read = ( remaining < bytes_in_page ) ? remaining : bytes_in_page;

				auto mapped_va = map_process_page( pa & ~( paging::page_4kb_size - 1 ) );
				if ( !mapped_va )
					return false;

				auto source = reinterpret_cast< std::uint8_t* >( mapped_va ) + ( pa & paging::page_4kb_mask );
				memcpy( current_dst, source, to_read );

				current_dst += to_read;
				current_page += to_read;
				remaining -= to_read;
			}

			return true;
		}

		bool write_virtual_ptm( const void* src, std::uint64_t va, std::size_t size ) {
			auto current_src = static_cast< const std::uint8_t* >( src );
			auto remaining = size;

			while ( remaining > 0 ) {
				std::uint32_t page_size = 0;
				bool writeable = false;
				auto pa = translate_linear( va, &page_size );
				if ( !pa )
					return false;

				auto page_offset = pa & ( page_size - 1 );
				auto bytes_in_page = page_size - page_offset;
				auto to_write = ( remaining < bytes_in_page ) ? remaining : bytes_in_page;

				auto mapped_va = map_process_page( pa & ~( paging::page_4kb_size - 1 ) );
				if ( !mapped_va )
					return false;

				auto dest = reinterpret_cast< std::uint8_t* >( mapped_va ) + ( pa & paging::page_4kb_mask );
				memcpy( dest, current_src, to_write );

				current_src += to_write;
				va += to_write;
				remaining -= to_write;
			}

			return true;
		}

		bool read_virtual( void* dst, std::uint64_t va, std::size_t size ) {
			if ( !dst || !size )
				return false;

			auto current_dst = static_cast< std::uint8_t* >( dst );
			auto current_va = va;
			auto remaining = size;

			while ( remaining > 0 ) {
				auto chunk_size = min( remaining, static_cast< std::size_t >( paging::page_4kb_size ) );

				if ( !read_virtual_single( current_dst, current_va, chunk_size ) )
					return false;

				current_dst += chunk_size;
				current_va += chunk_size;
				remaining -= chunk_size;
			}

			return true;
		}

		bool write_virtual( void* src, std::uint64_t va, std::size_t size ) {
			if ( !src || !size )
				return false;

			auto current_src = static_cast< std::uint8_t* >( src );
			auto current_va = va;
			auto remaining = size;

			while ( remaining > 0 ) {
				auto chunk_size = min( remaining, static_cast< std::size_t >( paging::page_4kb_size ) );

				if ( !write_virtual_single( current_src, current_va, chunk_size ) )
					return false;

				current_src += chunk_size;
				current_va += chunk_size;
				remaining -= chunk_size;
			}

			return true;
		}

		bool read_physical( void* dst, std::uint64_t pa, std::size_t size ) {
			if ( !dst || !size )
				return false;

			auto current_dst = static_cast< std::uint8_t* >( dst );
			auto current_pa = pa;
			auto remaining = size;

			while ( remaining > 0 ) {
				auto chunk_size = min( remaining, static_cast< std::size_t >( paging::page_4kb_size ) );

				if ( !read_physical_single( current_dst, current_pa, chunk_size ) )
					return false;

				current_dst += chunk_size;
				current_pa += chunk_size;
				remaining -= chunk_size;
			}

			return true;
		}

		bool write_physical( void* src, std::uint64_t pa, std::size_t size ) {
			if ( !src || !size )
				return false;

			auto current_src = static_cast< std::uint8_t* >( src );
			auto current_pa = pa;
			auto remaining = size;

			while ( remaining > 0 ) {
				auto chunk_size = min( remaining, static_cast< std::size_t >( paging::page_4kb_size ) );

				if ( !write_physical_single( current_src, current_pa, chunk_size ) )
					return false;

				current_src += chunk_size;
				current_pa += chunk_size;
				remaining -= chunk_size;
			}

			return true;
		}

		template <typename addr_t>
		bool read_memory( addr_t va, void* buffer, size_t size ) {
			std::uint64_t va64;
			if constexpr ( std::is_pointer_v<addr_t> ) {
				va64 = reinterpret_cast< std::uint64_t >( va );
			}
			else if constexpr ( std::is_integral_v<addr_t> ) {
				va64 = static_cast< std::uint64_t >( va );
			}
			else {
				static_assert( std::is_pointer_v<addr_t> || std::is_integral_v<addr_t>,
					"addr_t must be pointer or integral" );
			}

			if ( !buffer || !size )
				return false;

			return read_virtual( buffer, va64, size );
		}

		template <typename ret_t = std::uint64_t, typename addr_t>
		ret_t read( addr_t va ) {
			std::uint64_t va64;
			if constexpr ( std::is_pointer_v<addr_t> ) {
				va64 = reinterpret_cast< std::uint64_t >( va );
			}
			else if constexpr ( std::is_integral_v<addr_t> ) {
				va64 = static_cast< std::uint64_t >( va );
			}
			else {
				static_assert( std::is_pointer_v<addr_t> || std::is_integral_v<addr_t>,
					"addr_t must be pointer or integral" );
			}

			ret_t buffer{};
			if ( !read_memory( va64, &buffer, sizeof( ret_t ) ) )
				return {};

			return buffer;
		}

		template <typename addr_t>
		bool write_memory( addr_t va, void* buffer, size_t size ) {
			std::uint64_t va64;
			if constexpr ( std::is_pointer_v<addr_t> ) {
				va64 = reinterpret_cast< std::uint64_t >( va );
			}
			else if constexpr ( std::is_integral_v<addr_t> ) {
				va64 = static_cast< std::uint64_t >( va );
			}
			else {
				static_assert( std::is_pointer_v<addr_t> || std::is_integral_v<addr_t>,
					"addr_t must be pointer or integral" );
			}

			if ( !buffer || !size )
				return false;

			return write_virtual( buffer, va64, size );
		}

		template <typename val_t, typename addr_t>
		bool write( addr_t va, val_t value ) {
			return write_memory( va, &value, sizeof( val_t ) );
		}

		std::uint32_t get_process_id( std::wstring process_name ) {
			auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
			if ( snapshot == INVALID_HANDLE_VALUE )
				return false;

			PROCESSENTRY32W process_entry{ };
			process_entry.dwSize = sizeof( process_entry );
			Process32FirstW( snapshot, &process_entry );
			do {
				if ( !process_name.compare( process_entry.szExeFile ) )
					return process_entry.th32ProcessID;
			} while ( Process32NextW( snapshot, &process_entry ) );

			return 0;
		}

		HWND get_window_handle( std::uint32_t pid ) {
			std::pair<HWND, DWORD> params = { 0, pid };

			auto result = EnumWindows( [ ] ( HWND hwnd, LPARAM lParam ) -> int {
				auto pParams = ( std::pair<HWND, DWORD>* )( lParam );

				DWORD processId;
				if ( GetWindowThreadProcessId( hwnd, &processId ) && processId == pParams->second ) {
					SetLastError( -1 );
					pParams->first = hwnd;
					return false;
				}

				return true;

				}, reinterpret_cast< LPARAM >( &params ) );

			if ( !result && GetLastError( ) == -1 && params.first ) {
				return params.first;
			}

			return 0;
		}

		eprocess_t* get_eprocess( std::uint32_t process_id ) {
			m_control_data->m_request_type = control::control_type::eprocess;
			m_control_data->m_process_id = process_id;

			if ( !send_control( ) )
				return nullptr;

			return m_control_data->m_process;
		}

		std::uint64_t get_base_address( eprocess_t* eprocess ) {
			m_control_data->m_request_type = control::control_type::base;
			m_control_data->m_process = eprocess;

			if ( !send_control( ) )
				return 0;

			return reinterpret_cast< std::uint64_t >( m_control_data->m_address2 );
		}

		peb_t* get_process_peb( eprocess_t* eprocess ) {
			m_control_data->m_request_type = control::control_type::peb;
			m_control_data->m_process = eprocess;

			if ( !send_control( ) )
				return nullptr;

			return m_control_data->m_process_peb;
		}

		std::uint64_t get_directory_table_base( eprocess_t* eprocess ) {
			m_control_data->m_request_type = control::control_type::cr3;
			m_control_data->m_process = eprocess;

			if ( !send_control( 5000 ) )
				return 0;

			return m_control_data->m_address;
		}

		bool attach_process( std::wstring target_process ) {
			while ( true ) {
				this->m_process_id = this->get_process_id( target_process );
				if ( m_process_id ) 
					break;
			}

			while ( true ) {
				this->m_process_window = this->get_window_handle( m_process_id );
				if ( m_process_window )
					break;
			}

			this->m_eprocess = this->get_eprocess( m_process_id );
			if ( !m_eprocess ) {
				logging::print( oxorany( "Could not get EProcess." ) );
				return false;
			}

			this->m_process_peb = this->get_process_peb( m_eprocess );
			if ( !m_process_peb ) {
				logging::print( oxorany( "Could not get Process PEB." ) );
				return false;
			}

			this->m_base_address = this->get_base_address( m_eprocess );
			if ( !m_base_address ) {
				logging::print( oxorany( "Could not get base address." ) );
				return false;
			}

			this->m_directory_table_base = this->get_directory_table_base( m_eprocess );
			if ( !m_directory_table_base ) {
				logging::print( oxorany( "Could not get directory table base." ) );
				return false;
			}

			return true;
		}

		bool hyperspace_entries( paging::pt_entries_t& pt_entries, std::uint64_t va ) {
			m_control_data->m_request_type = control::control_type::hyperspace_entries;
			m_control_data->m_address = va;

			if ( !send_control( ) )
				return false;

			pt_entries = std::move( m_control_data->m_pt_entries );
			return true;
		}

	public:
		std::uint64_t translate_linear( std::uint64_t va, std::uint32_t* page_size = nullptr, bool use_cache = true ) {
			paging::pt_entries_t pt_entries;
			if ( !hyperspace_entries( pt_entries, va ) )
				return 0;

			std::uint64_t pa = 0;
			std::uint32_t size = 0;

			if ( pt_entries.m_pdpte.hard.page_size ) {
				pa = ( pt_entries.m_pdpte.hard.pfn << paging::page_shift ) + ( va & paging::page_1gb_mask );
				size = paging::page_1gb_size;
			}
			else if ( pt_entries.m_pde.hard.page_size ) {
				pa = ( pt_entries.m_pde.hard.pfn << paging::page_shift ) + ( va & paging::page_2mb_mask );
				size = paging::page_2mb_size;
			}
			else {
				pa = ( pt_entries.m_pte.hard.pfn << paging::page_shift ) + ( va & paging::page_4kb_mask );
				size = paging::page_4kb_size;
			}

			if ( page_size )
				*page_size = size;

			return pa;
		}

		void* map_process_page( std::uint64_t pa ) {
			m_control_data->m_request_type = control::control_type::map_process_page;
			m_control_data->m_address = pa;

			if ( !send_control( ) )
				return nullptr;

			return m_control_data->m_address2;
		}

		std::uint64_t allocate_virtual( std::size_t size, std::uint32_t protection ) {
			m_control_data->m_request_type = control::control_type::allocate_virtual;
			m_control_data->m_process_id = m_process_id;
			m_control_data->m_size = size;
			m_control_data->m_protection = protection;

			if ( !send_control( ) )
				return 0;

			return m_control_data->m_address;
		}

		ethread_t* lookup_thread( std::uint32_t thread_id ) {
			m_control_data->m_request_type = control::control_type::lookup_thread;
			m_control_data->m_process_id = thread_id;

			if ( !send_control( ) )
				return nullptr;

			return m_control_data->m_thread;
		}

		bool suspend_thread( ethread_t* thread, std::uint32_t* previous_suspend_count = nullptr ) {
			m_control_data->m_request_type = control::control_type::suspend_thread;
			m_control_data->m_thread = thread;

			if ( !send_control( ) )
				return false;

			if ( previous_suspend_count )
				*previous_suspend_count = m_control_data->m_count;

			return m_control_data->m_status;
		}

		bool resume_thread( ethread_t* thread, std::uint32_t* previous_suspend_count = nullptr ) {
			m_control_data->m_request_type = control::control_type::resume_thread;
			m_control_data->m_thread = thread;

			if ( !send_control( ) )
				return false;

			if ( previous_suspend_count )
				*previous_suspend_count = m_control_data->m_count;

			return m_control_data->m_status;
		}

		bool get_thread_context( ethread_t* thread, CONTEXT* out_context ) {
			if ( !out_context )
				return false;

			m_control_data->m_request_type = control::control_type::context;
			m_control_data->m_thread = thread;
			m_control_data->m_mode = 1;

			if ( !send_control( ) )
				return false;

			if ( m_control_data->m_status ) {
				memcpy( out_context, m_shared_buffer, sizeof( CONTEXT ) );
			}

			return m_control_data->m_status;
		}

		bool set_thread_context( ethread_t* thread, CONTEXT* in_context ) {
			if ( !in_context )
				return false;

			memcpy( m_shared_buffer, in_context, sizeof( CONTEXT ) );

			m_control_data->m_request_type = control::control_type::set_thread_context;
			m_control_data->m_thread = thread;
			m_control_data->m_mode = 1;

			if ( !send_control( ) )
				return false;

			return m_control_data->m_status;
		}

		bool hide_pages( std::uint64_t base_address, std::uint64_t size ) {
			m_control_data->m_request_type = control::control_type::hjijde_process;
			m_control_data->m_process = m_eprocess;
			m_control_data->m_address = base_address;
			m_control_data->m_size = size;

			if ( !send_control( ) )
				return false;

			return m_control_data->m_status;
		}

		std::uintptr_t get_process_module( const wchar_t* module_name ) {
			if ( !m_process_peb )
				return 0;
		}

		std::uintptr_t get_module_export( std::uintptr_t module_base, const char* export_name ) {
			if ( !module_base || !export_name )
				return 0;

			dos_header_t dos_header;
			if ( !read_memory( module_base, &dos_header, sizeof( dos_header_t ) ) )
				return 0;

			if ( !dos_header.is_valid( ) )
				return 0;

			nt_headers_t nt_headers;
			if ( !read_memory( module_base + dos_header.m_lfanew, &nt_headers, sizeof( nt_headers_t ) ) )
				return 0;

			if ( !nt_headers.is_valid( ) )
				return 0;

			auto export_dir_rva = nt_headers.m_export_table.m_virtual_address;
			auto export_dir_size = nt_headers.m_export_table.m_size;

			export_directory_t export_directory;
			if ( !read_memory( module_base + export_dir_rva, &export_directory, sizeof( export_directory_t ) ) )
				return 0;

			auto name_count = export_directory.m_number_of_names;
			std::vector<DWORD> names( name_count );
			if ( !read_memory(
				module_base + export_directory.m_address_of_names,
				names.data( ),
				name_count * sizeof( DWORD )
			) )
				return 0;

			if ( names.empty( ) )
				return 0;

			std::vector<WORD> ordinals( name_count );
			if ( !read_memory(
				module_base + export_directory.m_address_of_names_ordinals,
				ordinals.data( ),
				name_count * sizeof( WORD )
			) )
				return 0;

			if ( ordinals.empty( ) )
				return 0;

			for ( auto idx = 0; idx < name_count; idx++ ) {
				char name_buffer[ 256 ] = { 0 };
				if ( !read_memory( module_base + names[ idx ], name_buffer, sizeof( name_buffer ) - 1 ) )
					continue;
			}
		}

		struct module_info_t {
			std::uint64_t base;
			std::uint64_t size;
			std::wstring name;
		};

		std::vector< module_info_t > get_process_modules( ) {
			std::vector< module_info_t > modules;

			if ( !m_process_peb )
				return modules;

			auto peb_data = read< peb_t >( m_process_peb );
			if ( !peb_data.m_ldr )
				return modules;

			auto ldr_data = read< peb_ldr_data_t >( peb_data.m_ldr );
			auto current_entry = ldr_data.m_module_list_load_order.m_flink;
			auto first_entry = current_entry;

			do {
				auto entry = read< ldr_data_table_entry_t >( current_entry );

				if ( entry.m_base_dll_name.m_length > 0 &&
					entry.m_base_dll_name.m_length < MAX_PATH * 2 &&
					entry.m_dll_base ) {

					wchar_t name_buffer[ MAX_PATH ]{};
					if ( read_memory( entry.m_base_dll_name.m_buffer,
						name_buffer,
						entry.m_base_dll_name.m_length ) ) {

						name_buffer[ entry.m_base_dll_name.m_length / 2 ] = L'\0';
					}
				}

				current_entry = entry.m_in_load_order_module_list.m_flink;
			} while ( current_entry && current_entry != first_entry );

			return modules;
		}

		void test_speed( std::uint64_t address ) {
			std::uint64_t call_count = 0;
			auto start = std::chrono::high_resolution_clock::now( );
			auto end = start + std::chrono::seconds( 1 );

			while ( std::chrono::high_resolution_clock::now( ) < end ) {
				this->read<std::uint64_t>( address );
				call_count++;
			}

			auto actual_duration = std::chrono::high_resolution_clock::now( ) - start;
			double seconds = std::chrono::duration<double>( actual_duration ).count( );

			logging::print( "Completed %llu calls in %.6f seconds", call_count, seconds );
			logging::print( "Rate: %.2f calls per second",
				static_cast< double >( call_count ) / seconds );
		}
	};
}