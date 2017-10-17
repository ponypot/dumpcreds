#include	"header.h"



/**
** \fn void loadDefaultModule(sUserParam &infoParam)
** \brief Gere le chargement des modules par defaut
**
** \param infoParam Options selectionees par l'utilisateur
** \return Retourne rien
*/
void	loadDefaultModule(sUserParam &infoParam)
{
	infoParam.listFunctions.clear();

	for (unsigned long i=0; tabInfoModule[i].fExec!=NULL; i++)
	{
		if (tabInfoModule[i].useByDefault == 1)
		{
			infoParam.listFunctions.insert(tabInfoModule[i].fExec);
		}
	}
}

/**
** \fn int didUserSelectAModule(sUserParam &infoParam, const char *arg, int alreadeyHaveSelectedAModule)
** \brief Regarge si le parametre est une option de module et selectionne le module en question si besoin est
**
** \param infoParam Options selectionees par l'utilisateur
** \param arg Parametre utilisateur a identifier
** \param alreadeyHaveSelectedAModule Vaut 1 si l'utilisateur a deja selectionne un module
** \return Retourne 1 si le parametre etait une option de selection de module, 0 sinon
*/
int	didUserSelectAModule(sUserParam &infoParam, const char *arg, int alreadeyHaveSelectedAModule)
{
	for (unsigned long i=0; tabInfoModule[i].fExec!=NULL; i++)
	{
		/* Si le parametre correspond a l'option, on selctionne le module */
		if ((tabInfoModule[i].option != NULL) &&
		    (strlen(tabInfoModule[i].option) > 0) &&
		    (strcmp(tabInfoModule[i].option, arg) == 0))
		{
			/* Si on avait pas deja manuellement selectionne de modules, on enleve les modules par defaut */
			if (alreadeyHaveSelectedAModule == 0)
			{
				infoParam.listFunctions.clear();
			}

			/* Ajoute le module a la liste et retourne 1 */
			infoParam.listFunctions.insert(tabInfoModule[i].fExec);
			return (1);
		}
	}

	return (0);
}

/**
** \fn int printModuleName(sInfoProcess &infoProcess)
** \brief Gere l'affichage du nom du module si "infoProcess.ptrCurreentModule" != NULL
**
** \param infoProcess Structure contenant les infos du processus a analyser
** \return Retourne 1 si on a affiche le nom du module, 0 sinon
*/
int		printModuleName(sInfoProcess &infoProcess)
{
	for (unsigned long i=0; tabInfoModule[i].fExec!=NULL; i++)
	{
		if (infoProcess.ptrCurrentModule == (void*)(tabInfoModule[i].fExec))
		{
			printf("  %s:\n", tabInfoModule[i].name);

			/* Pour ne pas le reafficher */
			infoProcess.ptrCurrentModule = NULL;
			return (1);
		}		
	}
	
	return (0);
}

