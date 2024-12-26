#ifndef _TRACE_H_
#define _TRACE_H_
//
//   Author(s)    : Radu PORTASE(rportase@bitdefender.com)
//
//
// 
// WPP Control GUID for MyDriver: A4F04D82-3359-4B64-B2D0-D42F723C1857
#define WPP_CONTROL_GUIDS                                              \
    WPP_DEFINE_CONTROL_GUID(                                           \
        MyDriverTraceGuid, (A4F04D82,3359,4B64,B2D0,D42F723C1857),      \
        WPP_DEFINE_BIT(TRACE_FLAG_CORE)      /* bit  0 = 0x00000001 */ \
        )
//
// Because we are using our custom logging function LogMessage(Flags, Level, Message, ...) we need to define the flowing macros
//
#define WPP_LEVEL_FLAGS_LOGGER(lvl,flags) WPP_LEVEL_LOGGER(flags)
#define WPP_LEVEL_FLAGS_ENABLED(lvl,flags) (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level  >= lvl)


#define WPP_LEVEL_FLAGS_TIMESTAMP_LOGGER(lvl, flags, tmpstamp) WPP_LEVEL_LOGGER(flags)
#define WPP_LEVEL_FLAGS_TIMESTAMP_ENABLED(lvl, flags, tmpstamp) WPP_LEVEL_FLAGS_ENABLED(lvl, flags)

//
// Here we define our logging functions
//
// begin_wpp config
//
// FUNC LogTrace{LEVEL=TRACE_LEVEL_VERBOSE, FLAGS=TRACE_FLAG_CORE}(MSG, ...);
// FUNC LogInfo{LEVEL=TRACE_LEVEL_INFORMATION, FLAGS=TRACE_FLAG_CORE}(MSG, ...);
// FUNC LogWarning{LEVEL=TRACE_LEVEL_WARNING, FLAGS=TRACE_FLAG_CORE}(MSG, ...);
// FUNC LogError{LEVEL=TRACE_LEVEL_ERROR, FLAGS=TRACE_FLAG_CORE}(MSG, ...);
// FUNC LogCritical{LEVEL=TRACE_LEVEL_CRITICAL, FLAGS=TRACE_FLAG_CORE}(MSG, ...);
//
//
// end_wpp
//

#endif//_TRACE_H_