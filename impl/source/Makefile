OBJECT_ROOT         ?= _build/objects
OUT                 ?= _build/artifacts
TARGET              ?= run
EXPORT_PATH         ?= $(OUT)/$(TARGET)
LITAI_LANGUAGE_TOOL ?= python3
SRCS                := main.py $(wildcard tripwire/*.py) $(wildcard tests/*.py)

.PHONY: all test clean

all:
	"$(LITAI_LANGUAGE_TOOL)" -B tools/build_zipapp.py --source . --output "$(EXPORT_PATH)"

test: all
	PYTHONDONTWRITEBYTECODE=1 "$(LITAI_LANGUAGE_TOOL)" -B -m unittest discover -s tests -t . -p 'litai_test.py'
	"$(LITAI_LANGUAGE_TOOL)" -B tools/check_export.py "$(EXPORT_PATH)"

clean:
	"$(LITAI_LANGUAGE_TOOL)" -B tools/clean.py "$(OUT)" "$(OBJECT_ROOT)"
