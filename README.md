# Project Honeypot Http:BL Library

A simple PHP library for querying the [Project Honeypot Http:BL API](http://www.projecthoneypot.org/httpbl_api.php).

[![Build Status](https://travis-ci.org/thasmo/php.honeypot-blacklist.svg?branch=develop)](https://travis-ci.org/thasmo/php.honeypot-blacklist)
[![Coverage Status](https://coveralls.io/repos/thasmo/php.honeypot-blacklist/badge.svg?branch=develop)](https://coveralls.io/r/thasmo/php.honeypot-blacklist?branch=develop)
[![Latest Stable Version](https://poser.pugx.org/thasmo/honeypot-blacklist/v/stable)](https://packagist.org/packages/thasmo/honeypot-blacklist)

## Usage

### Create a new instance
```php
use Thasmo\ProjectHoneypot\Blacklist;
$client = new Blacklist('127.0.0.1', 'api-key');
```

### Create multiple instances
```php
use Thasmo\ProjectHoneypot\Blacklist;

# Set default API key.
Blacklist::setDefaultKey('api-key');

# Use the default API key.
$clientOne = new Blacklist('127.0.0.1');

# Use a specific API key.
$clientTwo = new Blacklist('127.0.0.2', 'other-api-key');

# Use the default API key, again.
$clientThree = new Blacklist('127.0.0.3');
```

### Check for various types of clients
```php
# Client is a search engine.
$client->isSearchEngine();

# Client is suspicious.
$client->isSuspicious();

# Client is a harvester.
$client->isHarvester()

# Client is a spammer.
$client->isSpammer();

# Client is blacklisted.
# Which means it is suspicious, a harvester or a spammer but not a search engine.
$client->isListed();
```

### Get last activity
```php
# Get the last activity for the client in days.
$lastActivity = $client->getActivity(); 
```

### Get threat score
```php
# Get the threat score of the client.
$threatScore = $client->getThreat();
```

### Check last activity
```php
# Check if the client was active in the last 10 days.
$isActive = $client->isActive(10);
```

### Check threat score
```php
# Check if the threat score is within the limit of 100.
$isThreat = $client->isThreat(100);
```

### Get the name for a search engine
```php
# Get the name of the search engine.
if($client->isSearchEngine()) {
  $name = $client->getName();
}
```

### Get the API result
```php
# Return an array holding the result from the API call
$result = $client->getResult();
```

### Change the address
```php
use Thasmo\ProjectHoneypot\Blacklist;

# Create an instance
$client = new Blacklist('127.0.0.1', 'api-key');

# Get the result
$result1 = $client->getResult();

# Set a new address which resets the object
$client->setAddress('127.0.0.2');

# Get the new result
$result2 = $client->getResult();
```

### Query the API
```php
use Thasmo\ProjectHoneypot\Blacklist;

# Create an instance
$client = new Blacklist('127.0.0.1', 'api-key');

# Query the API immediately
$client->query();

# Use other methods
if($client->isSearchEngine()) {
  $name = $client->getName();
}
```

## Implementation Details

* Requests to the API are delayed until you first call a method like `isSearchEngine` etc. or `query` explicitly.
* API responses for the same IP address on the same instance will be cached, the API will be queried only once.
* When changing the IP address via `setAddress` the cache is cleared and the API will be queried again.
