#include <impl/includes.h>

int main( int argc, char** argv ) {
	SetConsoleTitleA( oxorany( "calamari-fortnite" ) );
	SetUnhandledExceptionFilter( crash::crash_handler );

	auto std_handle = GetStdHandle( STD_OUTPUT_HANDLE );
	DWORD mode;
	GetConsoleMode( std_handle, &mode );
	mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode( std_handle, mode );

	CONSOLE_FONT_INFOEX cfi{ };
	cfi.cbSize = sizeof( cfi );
	cfi.nFont = 0;
	cfi.dwFontSize.X = 8;
	cfi.dwFontSize.Y = 15;
	cfi.FontFamily = FF_DONTCARE;
	cfi.FontWeight = FW_NORMAL;
	wcscpy_s( cfi.FaceName, oxorany( L"Raster Fonts" ) );
	SetCurrentConsoleFontEx( GetStdHandle( STD_OUTPUT_HANDLE ), FALSE, &cfi );

	if ( argc < 2 ) {
		logging::print( oxorany( "No DLL path provided." ) );
		logging::print( oxorany( "Usage: %s <path_to_dll>" ), argv[ 0 ] );
		return std::getchar( );
	}

	if ( !g_driver->create( ) ) {
		logging::print( oxorany( "Could not create communication" ) );
		return std::getchar( );
	}

	if ( !g_driver->initialize( ) ) {
		logging::print( oxorany( "Could not initialize communication." ) );
		return std::getchar( );
	}

	if ( !g_driver->is_active( ) ) {
		logging::print( oxorany( "Could not verify driver status." ) );
		return std::getchar( );
	}

	logging::print( oxorany( "Successfully initialized communication" ) );

	if ( !g_driver->attach_process( oxorany( L"FortniteClient-Win64-Shipping.exe" ) ) ) {
		logging::print( oxorany( "Could not attach to process." ) );
		return std::getchar( );
	}

	auto watchdog_start = std::chrono::steady_clock::now( );
	auto watchdog_timeout = std::chrono::minutes( 1 );

	while ( std::chrono::steady_clock::now( ) - watchdog_start < watchdog_timeout ) {
		if ( g_driver->get_process_module( oxorany( L"DiscordHook64.dll" ) ) )
			break;

		Sleep( 1 );
	}

	logging::print( oxorany( "Successfully attached to Fortnite\n" ) );

	auto dependency = std::make_shared< dependency::c_dependency >( argv[ 1 ] );
	if ( !dependency->is_dll( ) ) {
		logging::print( oxorany( "Could not load dependency." ) );
		return std::getchar( );
	}

	if ( !dependency->map( ) ) {
		logging::print( oxorany( "Could not map dependency." ) );
		return std::getchar( );
	}

	if ( !dependency->inject( ) ) {
		logging::print( oxorany( "Could not inject dependency." ) );
		return std::getchar( );
	}

	dependency->cleanup( );
	return std::getchar( );
}