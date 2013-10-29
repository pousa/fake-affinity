BASE_NAME=filter_affinity
TARGET_LIB=$(BASE_NAME).so.0.0.1

all: $(TARGET_LIB)

$(TARGET_LIB): $(BASE_NAME).c
	gcc -c -fPIC -rdynamic -Wall $(BASE_NAME).c
	gcc -shared -Wl,-soname,$(BASE_NAME).so.0 -o $(TARGET_LIB) $(BASE_NAME).o -ldl  -lc

clean:
	rm -f $(TARGET_LIB)
