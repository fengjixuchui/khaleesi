#ifndef MURMURHASH_H
#define MURMURHASH_H

/*
 * MurmurHash2A - Процедура хеширования по алгоритму MurmurHash2A (https://ru.wikipedia.org/wiki/MurmurHash2)
 * Аргументы:
 * const void *key - Указатель на буфер, который будем хешировать.
 * int len - Длина буфера.
 * unsigned int seed - Начальное значения для инициализации
*/

unsigned int MurmurHash2A(const void* key, int len, unsigned int seed);

#endif //MURMURHASH_H
