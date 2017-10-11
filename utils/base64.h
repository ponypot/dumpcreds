#ifndef	HEADER_BASE64_H
#define	HEADER_BASE64_H

#include	<inttypes.h>
#include	<string.h>



/**
** \fn int base64encode(const void* data, unsigned long dataLength,
**                      char* result, unsigned long resultSize)
** \brief Gere l'encodage d'un buffer en base64
**
** \param data Buffer contenant les donnees a encoder
** \param dataLength Taille des donnees a encoder
** \param result Buffer ou mettres les donnees encodees
** \param resultSize Taille du buffer de destination
** \return Retourne 1 si OK, -1 sinon
*/
int	base64encode(const void* data, unsigned long dataLength,
			char* result, unsigned long resultSize);

/**
** \fn int base64decode(const char *data, unsigned long dataLength,
**			unsigned char *result, unsigned long *resultSize)
** \brief Gere le de-encodage de donnees encodees en base64
**
** \param data Chaine en base64
** \param dataLength Taille de la chaine en base64
** \param result Buffer ou mettre les donnees de-encodees
** \param resultSize Pointeur sur la taille des donnees de-encodees
** \return Retourne 1 si OK, -1 sinon
*/
int	base64decode(const char *data, unsigned long dataLength,
			unsigned char *result, unsigned long *resultSize);

#endif

