#pragma once
#ifndef  _CRT_H
#define _CRT_H
 


namespace crt
{
	template <typename t>
	__forceinline int strlen(t str);

	bool strcmp(const char* src, const char* dst);



}

#endif // ! _CRT_H
