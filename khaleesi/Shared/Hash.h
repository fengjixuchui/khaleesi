/*
 * Copyright 2017 - 2018 Justas Masiulis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once
#define hashstr(name) khash(name)

// hashing stuff
struct hash_t
{
#define HASH_PRIME 16777619
#define HASH_OFFSET 2166136261

#define TOLOWER(c) (c >= 'A' && c <= 'Z' ? (c | (1 << 5)) : c)

	using value_type = unsigned long;
	constexpr static value_type offset = HASH_OFFSET;
	constexpr static value_type prime = HASH_PRIME;
	constexpr static unsigned long long prime64 = prime;

	FORCEINLINE constexpr static value_type single(value_type value,
	                                               char c) noexcept
	{
		return static_cast<hash_t::value_type>(
			(value ^ TOLOWER(c)) *
			static_cast<unsigned long long>(prime));
	}
};

template <class CharT = char>
FORCEINLINE constexpr hash_t::value_type khash(const CharT* str, hash_t::value_type value = hash_t::offset) noexcept
{
	return (*str ? khash(str + 1, hash_t::single(value, *str)) : value);
}

template <class CharT = char>
FORCEINLINE hash_t::value_type GetHash(const CharT* str) noexcept
{
	hash_t::value_type value = hash_t::offset;

	for (;;)
	{
		auto c = *str++;
		if (!c)
			return value;
		value = hash_t::single(value, c);
	}
}

FORCEINLINE hash_t::value_type GetHash(
	const UNICODE_STRING& str) noexcept
{
	auto first = str.Buffer;
	const auto last = first + (str.Length / sizeof(wchar_t));
	auto value = hash_t::offset;
	for (; first != last; ++first)
		value = hash_t::single(value, static_cast<char>(*first));

	return value;
}
