package main

import "github.com/atontalapur/signalman/internal/corpus"

// corpusEvent is one decoded corpus line and where it came from.
type corpusEvent = corpus.Event

// readCorpus reads the corpus under dir; see corpus.Read.
func readCorpus(dir string) ([]corpusEvent, error) { return corpus.Read(dir) }
