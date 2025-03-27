#!/bin/bash

RUSTFLAGS="-C target_cpu=native" \
	cargo bench --no-default-features \
	--features std,rayon,discrete_log,nightly \
	"$@"
