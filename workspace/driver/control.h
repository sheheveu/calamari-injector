#pragma once

namespace driver {
	namespace paging {
		constexpr auto page_4kb_size = 0x0;
		constexpr auto page_2mb_size = 0x0;
		constexpr auto page_1gb_size = 0x0;

		constexpr auto page_shift = 0x0;
		constexpr auto page_2mb_shift = 0x0;
		constexpr auto page_1gb_shift = 0x0;

		constexpr auto page_4kb_mask = 0x0;
		constexpr auto page_2mb_mask = 0x0;
		constexpr auto page_1gb_mask = 0x0;

		struct pt_entries_t {
			pml4e m_pml4e;
			pdpte m_pdpte;
			pde m_pde;
			pte m_pte;
		};

		enum class page_protection : std::uint8_t {
			readwrite_execute = 0,
			readwrite,
			inaccessible
		};

		std::unordered_map< std::uint64_t,
			std::pair<std::uint64_t, std::uint32_t> > m_virtual_address_space;
	}

	namespace control {
		struct control_initialize_t {
			std::uint64_t m_process_id;
			std::uint64_t m_base_address;
			void* m_response_semaphore;
			void* m_request_event;
		};

		enum control_type {
			none = 0,
			verify,
			eprocess,
			peb,
			base,
			cr3,
			hyperspace_entries,
			hjijde_process,
			map_process_page,
			read_physical,
			write_physical,
			write_virtual,
			read,
			allocate_virtual,
			free_virtual,
			lookup_thread,
			suspend_thread,
			resume_thread,
			context,
			set_thread_context,
			unload_driver
		};

		struct control_data_t {
			volatile long m_response_ready;
			control_type m_request_type;
			paging::pt_entries_t m_pt_entries;
			pml4e m_pml4e;
			pdpte m_pdpte;
			pde m_pde;
			pte m_pte;
			std::uint32_t m_process_id;
			std::uint32_t m_protection;
			std::uint32_t m_count;
			std::uint32_t m_mode;
			CONTEXT* m_context;
			eprocess_t* m_process;
			ethread_t* m_thread;
			peb_t* m_process_peb;
			std::uint64_t m_address;
			std::uint64_t m_address1;
			void* m_address2;
			std::size_t m_size;
			bool m_status;
		};
	}
}