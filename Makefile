SRC=	main.cpp \
	identParam.cpp \
	dumpMemory.cpp \
	module.cpp \
	\
	utils/base64.cpp \
	utils/hmacmd5.cpp \
	utils/md4.cpp \
	utils/md5.cpp \
	\
	moduleAuthBasic.cpp \
	moduleSearchString.cpp \
	moduleShadow.cpp \
	moduleStrings.cpp \
	moduleThunderbird.cpp
OBJ=	$(SRC:.cpp=.o)
BIN=	dumpcreds

CXX=		g++
CXXLIBS=	-lcrypt
CXXFLAGS=	-W -Wall -Wextra
#CXXFLAGS+=	-static	# Pour pouvoir fonctionner sur les systemes ou les libs ne sont pas installees
#CXXFLAGS+=	-O2	# Roarrr


all: $(BIN)

$(BIN): $(OBJ)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(CXXLIBS)

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(BIN)

re: fclean all

