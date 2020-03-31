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
func NewDataStore(options Options) (*DataStore, error) {
	result := DataStore{}
	config := bigcache.Config {
		// number of shards (must be a power of 2)
		Shards: 1024,

		// time after which entry can be evicted
		LifeWindow: 0,

		// Interval between removing expired entries (clean up).
		// If set to <= 0 then no action is performed.
		// Setting to < 1 second is counterproductive — bigcache has a one second resolution.
		CleanWindow: 0,

		// rps * lifeWindow, used only in initial memory allocation
		MaxEntriesInWindow: 1000 * 10 * 60,

		// max entry size in bytes, used only in initial memory allocation
		MaxEntrySize: 500,

		// prints information about additional memory allocation
		Verbose: true,

		// cache will not allocate more memory than this limit, value in MB
		// if value is reached then the oldest entries can be overridden for the new ones
		// 0 value means no size limit
		HardMaxCacheSize: maxCacheSizeInMB,

		// callback fired when the oldest entry is removed because of its expiration time or no space left
		// for the new entry, or because delete was called. A bitmask representing the reason will be returned.
		// Default value is nil which means no callback and it prevents from unwrapping the oldest entry.
		OnRemove: nil,

		// OnRemoveWithReason is a callback fired when the oldest entry is removed because of its expiration time or no space left
		// for the new entry, or because delete was called. A constant representing the reason will be passed through.
		// Default value is nil which means no callback and it prevents from unwrapping the oldest entry.
		// Ignored if OnRemove is specified.
		OnRemoveWithReason: nil,
	}
	cache, err := bigcache.NewBigCache(config)
	if err != nil || cache == nil {
		return nil, err
	}
	result.cache = cache
	return &result, nil
}
