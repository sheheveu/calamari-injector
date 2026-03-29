#pragma once

namespace logging {
    template<typename... Args>
    inline void print( const char* format, Args... args ) {
        auto now = std::chrono::system_clock::now( );
        std::time_t time = std::chrono::system_clock::to_time_t( now );
        tm local_tm;
        localtime_s( &local_tm, &time );
        printf( oxorany( "\x1b[38;2;176;31;40m[\x1b[38;2;174;34;42m%02d\x1b[38;2;172;37;44m/\x1b[38;2;170;40;46m%02d\x1b[38;2;168;43;48m/\x1b[38;2;166;46;50m%04d\x1b[38;2;164;49;52m \x1b[38;2;162;52;54m%02d\x1b[38;2;160;50;50m:\x1b[38;2;160;50;50m%02d\x1b[38;2;160;50;50m:\x1b[38;2;160;50;50m%02d]\x1b[0m " ),
            local_tm.tm_mon + 1,
            local_tm.tm_mday,
            local_tm.tm_year + 1900,
            local_tm.tm_hour,
            local_tm.tm_min,
            local_tm.tm_sec );
        printf( oxorany( "\x1b[38;2;160;50;50m[calamari]\x1b[0m " ) );
        printf( oxorany( "\x1b[37m" ) );
        printf( format, args... );
        printf( oxorany( "\x1b[0m\n" ) );
    }
}