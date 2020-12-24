ARCHITECTURE=bmv2

SOURCE_DIR=src
SOURCES:=$(wildcard $(SOURCE_DIR)/*.p4)
BUILD_DIR=build

P4C=p4c
P4C_FLAGS:=-b $(ARCHITECTURE) -I$(SOURCE_DIR)

5g.p4: $(SOURCES)
	$(P4C) $(P4C_FLAGS) -o $(BUILD_DIR) $(SOURCE_DIR)/5g.p4

run: $(SOURCES)
	sudo python 1sw_demo.py --behavioral-exe /usr/local/bin/simple_switch --mode l2 --json build/5g.json 

clean:
	rm -rf $(BUILD_DIR)

