
CC     = gcc
CFLAGS = -Wall 
LL     = -lssl -lcrypto
EXE    = certcheck
OBJ    = certcheck.o


$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $(EXE) $(OBJ) $(LL)

certcheck.o: certcheck.c


clean:
	rm -f $(OBJ) $(EXE)
