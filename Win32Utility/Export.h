/** 
    Author: Morgan.Li
    Date: 2018.10.18
*/

#ifndef __EXPORT_H__
#define __EXPORT_H__

#ifdef UTILITY_EXPORT
#define UTILITY_API __declspec(dllexport)
#else
#define UTILITY_API __declspec(dllimport)
#endif


#endif  // __EXPORT_H__
