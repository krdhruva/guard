/*
Copyright The Guard Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package data

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/allegro/bigcache"
)

const (
	maxCacheSizeInMB = 7
)

type DataStore struct {
	cache *bigcache.BigCache
}

// Set stores the given value for the given key.
// The key must not be "" and the value must not be nil.

func (s DataStore) Set(key string, value interface{}) error {
	if key == "" || value == nil {
		return errors.New("invalid key value pair")
	}

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.cache.Set(key, data)
}

// Get retrieves the Stored value for the given key.
// If no value is found it returns (false, nil).
// The key must not be "" and the pointer must not be nil.

func (s DataStore) Get(key string, value interface{}) (found bool, err error) {
	if key == "" || value == nil {
		return false, errors.New("invalid key value pair")
	}

	data, err := s.cache.Get(key)
	if err != nil {
		return false, err
	}
	return true , json.Unmarshal(data, value)
}

// Delete deletes the stored value for the given key.
// The key must not be "".

func (s DataStore) Delete(key string) error {
	if key == "" {
		return errors.New("invalid key")
	}

	err := s.cache.Delete(key)
	if err != nil {
		return err
	}
	return nil
}

// Close closes the DataStore.
// When called, the cache is left for removal by the garbage collector.
func (s DataStore) Close() error {
	return s.cache.Close()
}

// Options are the options for the BigCache store.
type Options struct {
	// The maximum size of the cache in MiB.
	// 0 means no limit.
	// Optional (0 by default, meaning no limit).
	HardMaxCacheSize int
	// Time after which an entry can be evicted.
	// 0 means no eviction.
	// When this is set to 0 and HardMaxCacheSize is set to a non-zero value
	// and the maximum capacity of the cache is reached
	// the oldest entries will be evicted nonetheless when new ones are stored.
	// Optional (0 by default, meaning no eviction).
	Eviction time.Duration
}

// DefaultOptions is an Options object with default values.
// HardMaxCacheSize: 0 (no limit), Eviction: 0 (no limit), MarshalFormat: JSON
var DefaultOptions = Options{
	// No need to set Eviction, HardMaxCacheSize or MarshalFormat
	// because their zero values are fine.
	HardMaxCacheSize : maxCacheSizeInMB,
}

// NewStore creates a BigCache store.
func NewDataStore(options Options) (DataStore, error) {
	result := DataStore{}
	config := bigcache.DefaultConfig(options.Eviction)
	config.HardMaxCacheSize = options.HardMaxCacheSize
	cache, err := bigcache.NewBigCache(config)
	if err != nil {
		return result, err
	}
	result.cache = cache
	return result, nil
}
