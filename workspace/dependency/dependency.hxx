#pragma once
#include <random>

namespace dependency {
    struct exec_context_t {
        std::uint32_t m_status;
        std::uint64_t m_result;
    };

    struct module_range_t {
        std::uint64_t m_base;
        std::uint64_t m_size;
    };

    static std::unordered_map<std::wstring, std::uint64_t> m_mapped_modules;
    static SRWLOCK m_mapped_modules_lock = SRWLOCK_INIT;

    class c_dependency {
    public:
        c_dependency( const std::string& file_path ) {
            m_dependency_name = utility::ansi_to_wstring( file_path );

            std::ifstream file( file_path, std::ios::binary | std::ios::ate );
            if ( !file.is_open( ) ) {
                logging::print( oxorany( "Failed to open file: %s" ), file_path.c_str( ) );
                return;
            }

            const auto file_size = file.tellg( );
            m_dependency.resize( static_cast< size_t >( file_size ) );

            file.seekg( 0, std::ios::beg );
            if ( !file.read( reinterpret_cast< char* >( m_dependency.data( ) ), file_size ) ) {
                logging::print( oxorany( "Failed to read file: %s" ), file_path.c_str( ) );
                m_dependency.clear( );
                return;
            }

            this->m_dos_header = reinterpret_cast
                < dos_header_t* >( m_dependency.data( ) );
            if ( !m_dos_header->is_valid( ) ) {
                logging::print( oxorany( "Invalid DOS signature in: %s" ), file_path.c_str( ) );
                m_dependency.clear( );
                return;
            }

            this->m_nt_headers = reinterpret_cast
                < nt_headers_t* >( m_dependency.data( ) + m_dos_header->m_lfanew );
            if ( !m_nt_headers->is_valid( ) ) {
                logging::print( oxorany( "Invalid NT headers in: %s" ), file_path.c_str( ) );
                m_dependency.clear( );
                return;
            }

            this->m_section_header = reinterpret_cast< section_header_t* >( reinterpret_cast
                < std::uintptr_t >( m_nt_headers ) + m_nt_headers->m_size_of_optional_header + 0x18 );
            return;
        }

        bool is_dll( ) const {
            if ( !m_nt_headers )
                return false;

            return ( m_nt_headers->m_characteristics & 0x0 );
        }

        bool map( ) {
            if ( !this->add_section( oxorany( ".exec" ), sizeof( exec_context_t ) ) ) {
                logging::print( oxorany( "Could not allocate section\n" ) );
                return false;
            }

            this->m_dependency_size = this->size_of_image( );
            this->m_dependency_base = g_driver->allocate_virtual( m_dependency_size, PAGE_EXECUTE_READWRITE );
            if ( !m_dependency_base ) {
                logging::print( oxorany( "Failed to allocate virtual\n" ) );
                return false;
            }

            if ( !g_driver->translate_linear( m_dependency_base ) ) {
                logging::print( oxorany( "Failed to translate linear\n" ) );
                return false;
            }

            logging::print( oxorany( "Allocated: 0x%llx (0x%X bytes)" ),
                m_dependency_base, m_dependency_size );

            if ( !this->map_relocs( m_dependency_base ) ) {
                logging::print( oxorany( "Failed to map relocs\n" ) );
                return false;
            }

            logging::print( oxorany( "Relocations applied" ) );

            if ( !this->map_imports( ) ) {
                logging::print( oxorany( "Failed to map imports\n" ) );
                return false;
            }

            logging::print( oxorany( "Imports resolved" ) );

            if ( !this->map_sections( m_dependency_base ) ) {
                logging::print( oxorany( "Failed to map sections\n" ) );
                return false;
            }

            logging::print( oxorany( "Sections mapped" ) );
            return true;
        }

        bool inject( ) {
            static int reinject_attempts = 0;
            constexpr int max_reinject_attempts = 3;

            auto entry_point = this->get_export( oxorany( "DllMain" ) );
            if ( !entry_point ) {
                logging::print( oxorany( "Failed to find DllMain\n" ) );
                return false;
            }

            entry_point += m_dependency_base;
            logging::print( oxorany( "Entry point: 0x%llx\n" ), entry_point );

reinject:
            auto status_executing = 1;
            auto status_complete = 2;
            logging::print( oxorany( "Finding target thread..." ) );


            DWORD target_thread_id = 0;
            DWORD best_delta = MAXDWORD;

            HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
            if ( snapshot != INVALID_HANDLE_VALUE ) {
                THREADENTRY32 te32{ .dwSize = sizeof( THREADENTRY32 ) };

                if ( Thread32First( snapshot, &te32 ) ) {
                    do {
                        if ( te32.th32OwnerProcessID != g_driver->m_process_id )
                            continue;

                        if ( te32.tpDeltaPri < best_delta ) {
                            target_thread_id = te32.th32ThreadID;
                            best_delta = te32.tpDeltaPri;
                        }
                    } while ( Thread32Next( snapshot, &te32 ) );
                }

                CloseHandle( snapshot );
            }

            if ( !target_thread_id ) {
                logging::print( oxorany( "No thread found in target process" ) );
                return false;
            }

            logging::print( oxorany( "Thread ID: %d" ), target_thread_id );

            auto thread_object = g_driver->lookup_thread( target_thread_id );
            if ( !thread_object ) {
                logging::print( oxorany( "Failed to lookup thread object" ) );
                return false;
            }

            if ( !g_driver->suspend_thread( thread_object ) ) {
                logging::print( oxorany( "Failed to suspend thread" ) );
                return false;
            }

            logging::print( oxorany( "Thread suspended" ) );

            CONTEXT thread_context = {};
            if ( !g_driver->get_thread_context( thread_object, &thread_context ) ) {
                logging::print( oxorany( "Failed to get thread context" ) );
                return false;
            }

            auto original_rip = thread_context.Rip;
            logging::print( oxorany( "Original RIP: 0x%llX" ), original_rip );

            auto shellcode_address = g_driver->allocate_virtual( 256, PAGE_EXECUTE_READWRITE );
            if ( !shellcode_address ) {
                logging::print( oxorany( "Failed to allocate shellcode memory" ) );
                g_driver->resume_thread( thread_object );
                return false;
            }

            auto section_va =  get_section_by_name( oxorany( ".text" ) )->m_virtual_address;
            auto flags_va = section_va + offsetof( exec_context_t, m_status );
            auto result_va = section_va + offsetof( exec_context_t, m_result );

            std::vector<BYTE> shellcode;
            shellcode.insert( shellcode.end( ), { 0x50 } );
            shellcode.insert( shellcode.end( ), { 0x51 } );
            shellcode.insert( shellcode.end( ), { 0x52 } );
            shellcode.insert( shellcode.end( ), { 0x41, 0x50 } );
            shellcode.insert( shellcode.end( ), { 0x41, 0x51 } );
            shellcode.insert( shellcode.end( ), { 0x41, 0x52 } );
            shellcode.insert( shellcode.end( ), { 0x41, 0x53 } );
            shellcode.insert( shellcode.end( ), { 0x48, 0x89, 0xE5 } );

            shellcode.insert( shellcode.end( ), { 0x48, 0x83, 0xE4, 0xF0 } );
            shellcode.insert( shellcode.end( ), { 0x48, 0x83, 0xEC, 0x20 } );

            shellcode.insert( shellcode.end( ), { 0x48, 0xB8 } );
            shellcode.insert( shellcode.end( ),
                reinterpret_cast < std::uint8_t* >( &flags_va ),
                reinterpret_cast < std::uint8_t* >( &flags_va ) + sizeof( flags_va ) );

            shellcode.insert( shellcode.end( ), { 0x48, 0xB8 } );
            shellcode.insert( shellcode.end( ),
                reinterpret_cast < std::uint8_t* >( &original_rip ),
                reinterpret_cast < std::uint8_t* >( &original_rip ) + sizeof( original_rip ) );

            if ( !g_driver->write_memory( shellcode_address, shellcode.data( ), shellcode.size( ) ) ) {
                logging::print( oxorany( "Failed to write shellcode" ) );
                g_driver->resume_thread( thread_object );
                return false;
            }

            logging::print( oxorany( "Shellcode written: 0x%llX (%zu bytes)" ),
                shellcode_address, shellcode.size( ) );

            thread_context.Rip = shellcode_address;

            logging::print( oxorany( "RIP hijacked: 0x%llX -> 0x%llX" ), original_rip, shellcode_address );

            if ( !g_driver->resume_thread( thread_object ) ) {
                logging::print( oxorany( "Failed to resume thread" ) );
                return false;
            }

            auto thread_handle = OpenThread( THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, target_thread_id );
            if ( !thread_handle ) {
                logging::print( oxorany( "Failed to open thread handle (err=%u)" ), GetLastError( ) );
                g_driver->resume_thread( thread_object );
                return false;
            }

            if ( !g_driver->resume_thread( thread_object ) ) {
                logging::print( oxorany( "Failed to resume thread" ) );
                CloseHandle( thread_handle );
                return false;
            }

            logging::print( oxorany( "Thread resumed, executing DllMain..." ) );

            auto watchdog_start = std::chrono::steady_clock::now( );
            auto watchdog_timeout = std::chrono::seconds( 5 );
            bool watchdog_success = true;

            while ( true ) {
                auto flags = g_driver->read<std::uint32_t>( flags_va );
                if ( flags == status_complete ) {
                    auto result = g_driver->read( result_va );
                    logging::print( oxorany( "DllMain returned: %llu" ), result );
                    break;
                }

                if ( std::chrono::steady_clock::now( ) - watchdog_start > watchdog_timeout ) {
                    reinject_attempts++;
                    logging::print( oxorany( "Thread timeout during injection" ));

                    if ( reinject_attempts >= max_reinject_attempts ) {
                        logging::print( oxorany( "Injection max attempts reached\n" ) );
                        CloseHandle( thread_handle );
                        return false;
                    }

                    logging::print( oxorany( "Reattempting injection (%d/%d)...\n" ),
                        reinject_attempts + 1, max_reinject_attempts );

                    if ( !g_driver->suspend_thread( thread_object ) ) {
                        logging::print( oxorany( "Failed to suspend thread" ) );
                        CloseHandle( thread_handle );
                        return false;
                    }

                    thread_context.Rip = original_rip;
                    if ( !g_driver->set_thread_context( thread_object, &thread_context ) ) {
                        logging::print( oxorany( "Failed to restore thread context" ) );
                        g_driver->resume_thread( thread_object );
                        CloseHandle( thread_handle );
                        return false;
                    }

                    g_driver->resume_thread( thread_object );
                    CloseHandle( thread_handle );
                    goto reinject;
                }

                auto exit_code = STILL_ACTIVE;
                if ( !GetExitCodeThread( thread_handle, &exit_code ) ) {
                    logging::print( oxorany( "Could not get thread status: 0x%08X" ),
                        GetLastError( ) );
                    watchdog_success = false;
                    break;
                }

                if ( exit_code != STILL_ACTIVE ) {
                    if ( exit_code ) {
                        logging::print( oxorany( "Thread exited unexpectedly during injection: 0x%08X" ),
                            exit_code );
                    }

                    watchdog_success = !exit_code;
                    break;
                }

                if ( !g_driver->get_process_id( oxorany( L"FortniteClient-Win64-Shipping.exe" ) ) ) {
                    logging::print( oxorany( "Process exited unexpectedly during injection" ) );
                    watchdog_success = false;
                    break;
                }

                Sleep( 1 );
            }

            CloseHandle( thread_handle );
            if ( !watchdog_success )
                return false;

            logging::print( oxorany( "Injection complete\n" ) );
            return true;
        }

        bool cleanup( ) {
            if ( !this->erase_discarded_sec( m_dependency_base ) )
                return false;

            logging::print( oxorany( "Concealed pages: 0x%llx (0x%X bytes)" ), m_dependency_base, m_dependency_size );
            logging::print( oxorany( "Cleanup complete\n" ) );
            return true;
        }

        std::uint64_t get_base( ) const {
            return m_dependency_base;
        }

    private:
        std::wstring m_dependency_name{ };
        dos_header_t* m_dos_header{ nullptr };
        nt_headers_t* m_nt_headers{ nullptr };
        section_header_t* m_section_header{ nullptr };
        std::uint32_t m_dependency_size{ };
        std::uint64_t m_dependency_base{ };
        std::uint64_t m_section_base{ };
        std::vector<uint8_t> m_dependency{ };

        std::uint32_t size_of_image( ) const {
            return m_nt_headers->m_size_of_image;
        }

        bool map_relocs( std::uint64_t new_image_base ) {
            struct reloc_entry {
                std::uint32_t m_to_rva;
                std::uint32_t m_size;
                struct {
                    std::int16_t m_offset : 0xc;
                    std::int16_t m_type : 0x4;
                } m_item[ 0x1 ];
                std::int8_t m_pad0[ 0x2 ];
            };

            auto delta_offset{ new_image_base - m_nt_headers->m_image_base };
            auto reloc_ent{ reinterpret_cast< reloc_entry* >( rva_va( m_nt_headers->m_base_relocation_table.m_virtual_address ) ) };
            auto reloc_end{ reinterpret_cast< std::uintptr_t >( reloc_ent ) + m_nt_headers->m_base_relocation_table.m_size };
            if ( !reloc_ent ) {
                logging::print( oxorany( "No relocation table found" ) );
                return false;
            }

            std::uint32_t reloc_count = 0;
            while ( reinterpret_cast< std::uintptr_t >( reloc_ent ) < reloc_end && reloc_ent->m_size ) {
                auto records_count{ ( reloc_ent->m_size - sizeof( std::int8_t* ) ) >> 0x1 };
                for ( std::size_t i{}; i < records_count; i++ ) {
                    auto fix_type{ reloc_ent->m_item[ i ].m_type };
                    auto shift_delta{ reloc_ent->m_item[ i ].m_offset % 0x1000 };

                    if ( fix_type == 0x3 || fix_type == 0xa ) {
                        auto fix_va{ rva_va( reloc_ent->m_to_rva ) };
                        if ( !fix_va )
                            fix_va = reinterpret_cast< std::int8_t* >( m_dos_header );
                        *reinterpret_cast< std::uint64_t* >( fix_va + shift_delta ) += delta_offset;
                        reloc_count++;
                    }
                }

                reloc_ent = ( reloc_entry* )( ( std::uint8_t* )reloc_ent + reloc_ent->m_size );
            }

            logging::print( oxorany( "Applied relocations (delta: 0x%llX)" ), delta_offset );
            return true;
        }

        bool map_imports( ) {
            if ( !m_nt_headers->m_import_table.m_virtual_address ) {
                logging::print( oxorany( "No imports to resolve" ) );
                return true;
            }

            auto import_desc = reinterpret_cast< import_descriptor_t* >(
                rva_va( m_nt_headers->m_import_table.m_virtual_address ) );

            if ( !import_desc ) {
                logging::print( oxorany( "Failed to resolve import table RVA" ) );
                return false;
            }

            std::uint32_t module_count = 0;
            std::uint32_t import_count = 0;

            for ( auto descriptor = import_desc; descriptor->m_name; descriptor++ ) {
                auto module_name = reinterpret_cast< char* >( rva_va( descriptor->m_name ) );
                if ( !module_name ) {
                    logging::print( oxorany( "Failed to resolve module name RVA" ) );
                    return false;
                }

                module_count++;

                auto module_lib = LoadLibraryA( module_name );
                if ( !module_lib ) {
                    logging::print( oxorany( "Failed to load library: %s" ), module_name );
                    return false;
                }

                auto module_path = get_module_path( module_name, m_dependency_name );
                if ( module_path.empty( ) ) {
                    FreeLibrary( module_lib );
                    return false;
                }

                auto file_name = utility::strip_path( module_path );
                if ( file_name.empty( ) ) {
                    logging::print( oxorany( "Empty file name for module path: %ws" ), module_path.c_str( ) );
                    FreeLibrary( module_lib );
                    return false;
                }

                std::wstring file_name_lower = file_name;
                std::transform( file_name_lower.begin( ), file_name_lower.end( ),
                    file_name_lower.begin( ), ::towlower );

                auto module_base = g_driver->get_process_module( file_name.c_str( ) );
                if ( !module_base ) {

                    if ( !module_base ) {
                        {
                            AcquireSRWLockExclusive( &m_mapped_modules_lock );
                            m_mapped_modules[ file_name_lower ] = 0;
                            ReleaseSRWLockExclusive( &m_mapped_modules_lock );
                        }

                        logging::print( oxorany( "Module not in target, mapping dependency: %ws" ),
                            file_name.c_str( ) );

                        auto dep_path_ansi = utility::wstring_to_ansi( module_path );
                        c_dependency dep( dep_path_ansi );

                        module_base = dep.get_base( );
                        if ( !module_base ) {
                            logging::print( oxorany( "Mapped dependency has no base: %ws" ), file_name.c_str( ) );

                            AcquireSRWLockExclusive( &m_mapped_modules_lock );
                            m_mapped_modules.erase( file_name_lower );
                            ReleaseSRWLockExclusive( &m_mapped_modules_lock );

                            FreeLibrary( module_lib );
                            return false;
                        }

                        logging::print( oxorany( "Dependency mapped at: 0x%llX" ), module_base );

                    }
                }

                auto thunk = reinterpret_cast< image_thunk_data_t* >( rva_va( descriptor->m_first_thunk ) );
                if ( !thunk ) {
                    logging::print( oxorany( "Failed to resolve first thunk RVA" ) );
                    FreeLibrary( module_lib );
                    return false;
                }

                auto original_thunk = reinterpret_cast< image_thunk_data_t* >( rva_va( 0x0 ) );

                if ( !original_thunk ) {
                    logging::print( oxorany( "Failed to resolve original thunk RVA" ) );
                    FreeLibrary( module_lib );
                    return false;
                }

                std::uint32_t func_count = 0;
                for ( auto current_thunk = thunk; original_thunk->m_u1.m_address_of_data; original_thunk++, current_thunk++ ) {
                    std::uint64_t function = 0;

                    if ( original_thunk->m_u1.m_ordinal & IMAGE_ORDINAL_FLAG64 ) {
                        auto ordinal = ( std::uint16_t )( original_thunk->m_u1.m_ordinal & 0xFFFF );
                        function = reinterpret_cast< std::uint64_t >( GetProcAddress( module_lib, ( LPCSTR )ordinal ) );
                    }
                    else {
                        auto import_name = reinterpret_cast< image_import_name_t* >(
                            rva_va( original_thunk->m_u1.m_address_of_data ) );

                        if ( !import_name ) {
                            logging::print( oxorany( "Failed to resolve import name RVA" ) );
                            FreeLibrary( module_lib );
                            return false;
                        }

                        function = reinterpret_cast< std::uint64_t >( GetProcAddress( module_lib, import_name->m_name ) );
                    }

                    if ( !function ) {
                        logging::print( oxorany( "Failed to resolve import in: %s" ), module_name );
                        FreeLibrary( module_lib );
                        return false;
                    }

                    auto target_base = module_base;
                    auto local_base = reinterpret_cast< std::uint64_t >( module_lib );

                    auto offset = function - local_base;
                    current_thunk->m_u1.m_function = target_base + offset;

                    func_count++;
                    import_count++;
                }

                FreeLibrary( module_lib );
            }

            logging::print( oxorany( "Resolved %u imports from %u modules" ), import_count, module_count );
            return true;
        }

        bool add_section( const char* section_name, std::uint32_t size ) {
            auto& num_sections = m_nt_headers->m_number_of_sections;

            auto last_section = m_section_header + num_sections - 1;
            auto new_header = m_section_header + num_sections;

            memset( new_header, 0, sizeof( section_header_t ) );
            strncpy_s( reinterpret_cast< char* >( new_header->m_name ), 8, section_name, 8 );

            auto sec_align = m_nt_headers->m_section_alignment;
            auto file_align = m_nt_headers->m_file_alignment;

            auto aligned_va = [ ] ( std::uint32_t base, std::uint32_t align ) {
                return ( base + align - 1 ) & ~( align - 1 );
                };

            new_header->m_virtual_size = size;
            new_header->m_virtual_address = aligned_va(
                last_section->m_virtual_address + last_section->m_virtual_size, sec_align );

            new_header->m_characteristics = 0x0; 

            m_nt_headers->m_size_of_image = aligned_va(
                new_header->m_virtual_address + new_header->m_virtual_size, sec_align );

            num_sections++;
            return true;
        }

        bool map_sections( uint64_t new_image_base ) {
            auto section = m_section_header;
            std::uint32_t mapped_count = 0;
            std::uint32_t total_size = 0;

            for ( auto idx = 0; idx < m_nt_headers->m_number_of_sections; idx++, section++ ) {
                auto dst = new_image_base + section->m_virtual_address;
                auto raw_size = section->m_size_of_raw_data;
                auto virt_size = section->m_virtual_size;

                if ( raw_size > 0 ) {
                    auto src = reinterpret_cast< void* >(
                        m_dependency.data( ) + section->m_pointer_to_raw_data );

                    auto write_size = min( raw_size, virt_size );

                    if ( !g_driver->write_memory( dst, src, write_size ) ) {
                        char section_name[ 9 ] = { 0 };
                        memcpy( section_name, section->m_name, 8 );
                        logging::print( oxorany( "Failed to write section: %.8s" ), section_name );
                        return false;
                    }
                }

                char section_name[ 9 ] = { 0 };
                memcpy( section_name, section->m_name, 8 );
                logging::print( oxorany( "%-8s -> 0x%llX" ),
                    section_name, dst );

                mapped_count++;
                total_size += virt_size;
            }

            logging::print( oxorany( "Mapped %u sections (%u bytes total)" ), mapped_count, total_size );
            return true;
        }

        bool erase_discarded_sec( uint64_t mapped_image_base ) {
            auto section = m_section_header;
            std::uint32_t erased_count = 0;

            for ( auto idx = 0; idx < m_nt_headers->m_number_of_sections; idx++, section++ ) {
                if ( section->m_characteristics & 0x0 ) {
                    auto size = section->m_virtual_size;
                    if ( !size )
                        continue;

                    auto dst = mapped_image_base + section->m_virtual_address;

                    std::vector<uint8_t> zero_buffer( size, 0 );
                    if ( !g_driver->write_memory( dst, zero_buffer.data( ), size ) ) {
                        char section_name[ 9 ] = { 0 };
                        memcpy( section_name, section->m_name, 8 );
                        logging::print( oxorany( "Could not erase section: %.8s" ), section_name );
                        return false;
                    }

                    char section_name[ 9 ] = { 0 };
                    memcpy( section_name, section->m_name, 8 );
                    logging::print( oxorany( "Erased: %.8s (0x%X bytes)" ), section_name, size );
                    erased_count++;
                }
            }

            if ( erased_count > 0 ) {
                logging::print( oxorany( "Erased %u discardable sections" ), erased_count );
            }

            return true;
        }

        std::uint32_t erase_strings( std::uint32_t max_length = 64 ) {
            auto rdata = get_section_by_name( ".rdata" );
            if ( !rdata ) {
                logging::print( oxorany( ".rdata section not found" ) );
                return 0;
            }

            auto payload = m_dependency.data( );
            std::uint32_t count = 0;

            for ( std::uint32_t idx = 0x1000;
                idx < rdata->m_virtual_address + rdata->m_virtual_size; idx++ ) {

                std::uint32_t length = 0;
                std::uintptr_t address = 0;

                for ( std::uint32_t len = 0; len < max_length; len++ ) {
                    const char& character = payload[ idx + len ];

                    if ( character < 0x20 || character > 0x2 ) {
                        if ( payload[ max( idx - 1, 1 ) ] != 0 || payload[ idx + len ] != 0 ) {
                            break;
                        }
                        length = len;
                        address = reinterpret_cast< std::uintptr_t >( payload ) + idx;
                        idx += len;
                        break;
                    }
                }

                if ( length > 4 ) {
                    count++;
                    memset( reinterpret_cast< void* >( address ), 0, length );
                }
            }

            logging::print( oxorany( "Erased %u strings from .rdata" ), count );
            return count;
        }
        struct thread_debug_info_t {
            DWORD   thread_id;
            int     score;
            DWORD64 rip;
            wchar_t module_name[ MAX_PATH ];
            LONG    base_priority;
            FILETIME creation_time;
            FILETIME kernel_time;
            FILETIME user_time;
            std::string wait_reason;
            bool in_kernel;
        };

        static const char* decode_wait_reason( ULONG reason ) {
            // KWAIT_REASON enum
            switch ( reason ) {
                case 0:  return "Executive";
                case 1:  return "FreePage";
                case 2:  return "PageIn";
                case 3:  return "PoolAllocation";
                case 4:  return "DelayExecution";
                case 5:  return "Suspended";
                case 6:  return "UserRequest";
                case 7:  return "WrExecutive";
                case 8:  return "WrFreePage";
                case 9:  return "WrPageIn";
                case 10: return "WrPoolAllocation";
                case 11: return "WrDelayExecution";
                case 12: return "WrSuspended";
                case 13: return "WrUserRequest";
                case 14: return "WrEventPair";
                case 15: return "WrQueue";
                case 16: return "WrLpcReceive";
                case 17: return "WrLpcReply";
                case 18: return "WrVirtualMemory";
                case 19: return "WrPageOut";
                case 20: return "WrRendezvous";
                case 21: return "WrKeyedEvent";
                case 22: return "WrTerminated";
                case 23: return "WrProcessInSwap";
                case 24: return "WrCpuRateControl";
                case 25: return "WrCalloutStack";
                case 26: return "WrKernel";
                case 27: return "WrResource";
                case 28: return "WrPushLock";
                case 29: return "WrMutex";
                case 30: return "WrQuantumEnd";
                case 31: return "WrDispatchInt";
                case 32: return "WrPreempted";
                case 33: return "WrYieldExecution";
                case 34: return "WrFastMutex";
                case 35: return "WrGuardedMutex";
                case 36: return "WrRundown";
                case 37: return "WrAlertByThreadId";
                case 38: return "WrDeferredPreempt";
                default: return "Unknown";
            }
        }

        // Queries NtQuerySystemInformation for per-thread wait reasons.
        // Returns a map of ThreadId -> WaitReason (KWAIT_REASON).
        static std::unordered_map< DWORD, ULONG > get_thread_wait_reasons( ) {
            using NtQuerySystemInformation_t = NTSTATUS( WINAPI* )(
                ULONG, PVOID, ULONG, PULONG );

            static auto fn = reinterpret_cast< NtQuerySystemInformation_t >(
                GetProcAddress( GetModuleHandleW( L"ntdll.dll" ),
                    "NtQuerySystemInformation" ) );

            std::unordered_map< DWORD, ULONG > result;
            if ( !fn ) return result;

            // SystemProcessInformation = 5
            constexpr ULONG SystemProcessInformation = 5;

            ULONG buf_size = 1 << 22; // 4 MB initial
            std::vector< std::uint8_t > buf;

            NTSTATUS status;
            do {
                buf.resize( buf_size );
                ULONG returned = 0;
                status = fn( SystemProcessInformation, buf.data( ), buf_size, &returned );
                if ( status == 0xC0000004L /*STATUS_INFO_LENGTH_MISMATCH*/ )
                    buf_size *= 2;
            } while ( status == 0xC0000004L );

            if ( status != 0 ) return result;

            // Walk SYSTEM_PROCESS_INFORMATION
            struct SYSTEM_THREAD_INFORMATION {
                LARGE_INTEGER KernelTime;
                LARGE_INTEGER UserTime;
                LARGE_INTEGER CreateTime;
                ULONG         WaitTime;
                PVOID         StartAddress;
                CLIENT_ID     ClientId;
                LONG          Priority;
                LONG          BasePriority;
                ULONG         ContextSwitches;
                ULONG         ThreadState;   // 0=init,1=ready,2=running,3=standby,4=terminated,5=wait,6=transition,7=deferred
                ULONG         WaitReason;
            };
            struct SYSTEM_PROCESS_INFORMATION {
                ULONG          NextEntryOffset;
                ULONG          NumberOfThreads;
                LARGE_INTEGER  WorkingSetPrivateSize;
                ULONG          HardFaultCount;
                ULONG          NumberOfThreadsHighWatermark;
                ULONGLONG      CycleTime;
                LARGE_INTEGER  CreateTime;
                LARGE_INTEGER  UserTime;
                LARGE_INTEGER  KernelTime;
                UNICODE_STRING ImageName;
                LONG           BasePriority;
                HANDLE         UniqueProcessId;
                HANDLE         InheritedFromUniqueProcessId;
                ULONG          HandleCount;
                ULONG          SessionId;
                ULONG_PTR      UniqueProcessKey;
                SIZE_T         PeakVirtualSize;
                SIZE_T         VirtualSize;
                ULONG          PageFaultCount;
                SIZE_T         PeakWorkingSetSize;
                SIZE_T         WorkingSetSize;
                SIZE_T         QuotaPeakPagedPoolUsage;
                SIZE_T         QuotaPagedPoolUsage;
                SIZE_T         QuotaPeakNonPagedPoolUsage;
                SIZE_T         QuotaNonPagedPoolUsage;
                SIZE_T         PagefileUsage;
                SIZE_T         PeakPagefileUsage;
                SIZE_T         PrivatePageCount;
                LARGE_INTEGER  ReadOperationCount;
                LARGE_INTEGER  WriteOperationCount;
                LARGE_INTEGER  OtherOperationCount;
                LARGE_INTEGER  ReadTransferCount;
                LARGE_INTEGER  WriteTransferCount;
                LARGE_INTEGER  OtherTransferCount;
                SYSTEM_THREAD_INFORMATION Threads[ 1 ];
            };

            auto* proc = reinterpret_cast< SYSTEM_PROCESS_INFORMATION* >( buf.data( ) );
            while ( true ) {
                for ( ULONG t = 0; t < proc->NumberOfThreads; t++ ) {
                    auto& ti = proc->Threads[ t ];
                    auto  tid = static_cast< DWORD >(
                        reinterpret_cast< std::uintptr_t >( ti.ClientId.UniqueThread ) );
                    result[ tid ] = ti.WaitReason;
                }
                if ( !proc->NextEntryOffset ) break;
                proc = reinterpret_cast< SYSTEM_PROCESS_INFORMATION* >(
                    reinterpret_cast< std::uint8_t* >( proc ) + proc->NextEntryOffset );
            }
            return result;
        }

        DWORD find_target_thread( DWORD pid ) {
            HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
            if ( snapshot == INVALID_HANDLE_VALUE ) return 0;

            auto wait_reasons = get_thread_wait_reasons( );

            // Known-bad RIPs: these are all blocking syscall stubs in ntdll
            // You can verify these from your own logs — they never execute shellcode
            const std::unordered_set< DWORD64 > blocked_rips = {
                0x7FFE280ED624,  // NtWaitForSingleObject+0x14  (ret)
                0x7FFE280EE0F4,  // NtWaitForMultipleObjects (or similar) ret stub
                0x7FFE280ED6C4,  // Another ntdll wait stub
                0x7FFE280F1034,  // NtRemoveIoCompletion / IOCP wait
                0x7FFE280F0FD4,  // NtWaitForAlertByThreadId ret
                0x7FFE280F03D4,  // Another queue wait
                0x7FFE25DE1104,  // win32u wait stub
            };

            std::vector< thread_debug_info_t > candidates;

            THREADENTRY32 te32{ .dwSize = sizeof( THREADENTRY32 ) };
            if ( Thread32First( snapshot, &te32 ) ) {
                do {
                    if ( te32.th32OwnerProcessID != pid ) continue;

                    auto thread_handle = OpenThread(
                        THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                        FALSE, te32.th32ThreadID );
                    if ( !thread_handle ) continue;

                    auto thread_object = g_driver->lookup_thread( te32.th32ThreadID );
                    if ( !thread_object ) {
                        CloseHandle( thread_handle );
                        continue;
                    }

                    CONTEXT context{ };
                    if ( !g_driver->get_thread_context( thread_object, &context ) ) {
                        CloseHandle( thread_handle );
                        continue;
                    }

                    auto current_rip = context.Rip;
                    if ( !current_rip ) {
                        CloseHandle( thread_handle );
                        continue;
                    }

                    // Hard reject: known blocking syscall stubs
                    // These will NEVER execute shellcode reliably
                    if ( blocked_rips.count( current_rip ) ) {
                        logging::print( oxorany( "[TID %5u] RIP=0x%llX is a known blocking stub, skipping" ),
                            te32.th32ThreadID, current_rip );
                        CloseHandle( thread_handle );
                        continue;
                    }

                    return  te32.th32ThreadID;


                    thread_debug_info_t info{ };
                    info.thread_id = te32.th32ThreadID;
                    info.rip = current_rip;
                    info.base_priority = te32.tpBasePri;
                    info.score = 0;

                    HMODULE module = nullptr;
                    bool in_known_module = GetModuleHandleExW(
                        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        reinterpret_cast< const wchar_t* >( current_rip ),
                        &module );

                    if ( in_known_module ) {
                        GetModuleFileNameW( module, info.module_name, MAX_PATH );
                        const wchar_t* s = wcsrchr( info.module_name, L'\\' );
                        if ( s ) wcscpy_s( info.module_name, s + 1 );
                    }
                    else {
                        // RIP is in unmapped/JIT/injected memory — this is a 
                        // RUNNING or recently-running thread, best candidate
                        wcscpy_s( info.module_name, L"<jit/unmapped>" );
                        //info.score -= 50;  // Strong preference
                    }

                    auto wait_it = wait_reasons.find( te32.th32ThreadID );
                    ULONG wr = ( wait_it != wait_reasons.end( ) ) ? wait_it->second : 0xFF;

                    if ( wait_it != wait_reasons.end( ) )
                        info.wait_reason = decode_wait_reason( wr );
                    else
                        info.wait_reason = "N/A";

                    // ThreadState: 2 = Running, 1 = Ready — these are actively
                    // scheduled and will execute shellcode immediately
                    // (You can get this from the same NtQuerySystemInformation
                    //  SYSTEM_THREAD_INFORMATION::ThreadState field)
                    // For now score by wait reason
                    switch ( wr ) {
                        case 0xFF: info.score += 10; break;  // Unknown = probably running
                            // DO NOT reward WrUserRequest(6) — it's a blocking wait
                            // despite the "User" name. It just means called from user-mode.
                        default: break;
                    }

                    // Penalise ALL ntdll wait states heavily
                    // Any thread whose last user-mode RIP was a syscall stub
                    // is parked in the kernel and unreliable for hijacking
                    if ( in_known_module ) {
                        wchar_t mod_lower[ MAX_PATH ];
                        wcscpy_s( mod_lower, info.module_name );
                        _wcslwr_s( mod_lower );
                        if ( wcsstr( mod_lower, L"ntdll" ) || wcsstr( mod_lower, L"win32u" ) )
                            info.score -= 30;
                    }

                    FILETIME exit_time{}, dummy{};
                    GetThreadTimes( thread_handle,
                        &info.creation_time, &exit_time,
                        &info.kernel_time, &info.user_time );

                    ULONGLONG user_100ns =
                        ( static_cast< ULONGLONG >( info.user_time.dwHighDateTime ) << 32 )
                        | info.user_time.dwLowDateTime;
                    if ( user_100ns > 0 ) info.score += 5;

                    candidates.push_back( info );
                    CloseHandle( thread_handle );

                } while ( Thread32Next( snapshot, &te32 ) );
            }
            CloseHandle( snapshot );

            if ( candidates.empty( ) ) {
                logging::print( oxorany( "find_target_thread: no viable candidates" ) );
                return 0;
            }

            logging::print( oxorany( "---- Thread candidates (pid=%u, total=%zu) ----" ),
                pid, candidates.size( ) );
            for ( auto& c : candidates ) {
                ULONGLONG user_ms = ( ( static_cast< ULONGLONG >( c.user_time.dwHighDateTime ) << 32 )
                    | c.user_time.dwLowDateTime ) / 10000ULL;
                logging::print(
                    oxorany( "  [TID %5u] score=%+3d  RIP=0x%llX  wait=%-22s  user=%6llums  pri=%d  mod=%ws" ),
                    c.thread_id, c.score, c.rip,
                    c.wait_reason.c_str( ), user_ms,
                    c.base_priority, c.module_name );
            }
            logging::print( oxorany( "-----------------------------------------------" ) );

            std::sort( candidates.begin( ), candidates.end( ),
                [ ] ( const auto& a, const auto& b ) { return a.score > b.score; } );

            // Don't randomly pick among all score=+20 — only pick among the
            // absolute top scorers, which should now be the JIT/active threads
            int top_score = candidates.front( ).score;
            auto it = std::partition_point( candidates.begin( ), candidates.end( ),
                [ top_score ] ( const auto& a ) { return a.score >= top_score; } );

            std::vector< thread_debug_info_t > top( candidates.begin( ), it );
            std::mt19937 rng( std::random_device{ }( ) );
            std::uniform_int_distribution< std::size_t > dist( 0, top.size( ) - 1 );
            auto chosen = top[ dist( rng ) ];

            logging::print( oxorany( "Selected TID %u (score=%+d, wait=%s, RIP=0x%llX, mod=%ws)" ),
                chosen.thread_id, chosen.score,
                chosen.wait_reason.c_str( ), chosen.rip, chosen.module_name );

            return chosen.thread_id;
        }

        std::uint64_t get_export( const char* export_name ) {
            if ( !m_nt_headers->m_export_table.m_virtual_address )
                return 0;

            auto export_dir = reinterpret_cast< export_directory_t* >(
                rva_va( m_nt_headers->m_export_table.m_virtual_address ) );

            if ( !export_dir )
                return 0;

            auto functions = reinterpret_cast< std::uint32_t* >(
                rva_va( export_dir->m_address_of_functions ) );
            auto names = reinterpret_cast< std::uint32_t* >(
                rva_va( export_dir->m_address_of_names ) );
            auto ordinals = reinterpret_cast< std::uint16_t* >(
                rva_va( export_dir->m_address_of_names_ordinals ) );

            if ( !functions || !names || !ordinals )
                return 0;

            for ( auto idx = 0; idx < export_dir->m_number_of_names; idx++ ) {
                auto name = reinterpret_cast< const char* >( rva_va( names[ idx ] ) );
                if ( !name )
                    continue;

                if ( !std::strcmp( name, export_name ) ) {
                    auto ordinal = ordinals[ idx ];
                    if ( ordinal >= export_dir->m_number_of_functions )
                        return 0;

                    return functions[ ordinal ];
                }
            }

            return 0;
        }

        std::int8_t* rva_va( const std::ptrdiff_t rva ) {
            for ( auto p_section{ m_section_header }; p_section < m_section_header + m_nt_headers->m_number_of_sections; p_section++ )
                if ( rva >= p_section->m_virtual_address && rva < p_section->m_virtual_address + p_section->m_virtual_size )
                    return ( std::int8_t* )m_dos_header + p_section->m_pointer_to_raw_data + ( rva - p_section->m_virtual_address );
            return {};
        }

        section_header_t* get_section_by_name( const char* name ) {
            auto section = m_section_header;
            for ( auto idx = 0; idx < m_nt_headers->m_number_of_sections; idx++, section++ ) {
                if ( strncmp( reinterpret_cast< const char* >( section->m_name ), name, 8 ) == 0 ) {
                    return section;
                }
            }
            return nullptr;
        }
    };
}