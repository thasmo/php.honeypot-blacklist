<?php namespace Thasmo\ProjectHoneypot;

use InvalidArgumentException;

/**
 * Class Blacklist
 * @package Thasmo\ProjectHoneypot
 */
class Blacklist {
	const API_HOST = 'dnsbl.httpbl.org';

	const TYPE_SEARCH_ENGINE = 0;
	const TYPE_SUSPICIOUS = 1;
	const TYPE_HARVESTER = 2;
	const TYPE_SPAMMER = 4;

	const CLIENT_UNKNOWN = 0;
	const CLIENT_ALTAVISTA = 1;
	const CLIENT_ASK = 2;
	const CLIENT_BAIDU = 3;
	const CLIENT_EXCITE = 4;
	const CLIENT_GOOGLE = 5;
	const CLIENT_LOOKSMART = 6;
	const CLIENT_LYCOS = 7;
	const CLIENT_MSN = 8;
	const CLIENT_YAHOO = 9;
	const CLIENT_CUIL = 10;
	const CLIENT_INFOSEEK = 11;
	const CLIENT_OTHER = 12;

	/**
	 * Default API key to use.
	 * @var string
	 */
	protected static $defaultKey = NULL;

	/**
	 * API key to use.
	 * @var string
	 */
	protected $key = NULL;

	/**
	 * IP address to query.
	 * @var string
	 */
	protected $address = NULL;

	/**
	 * Transformed result from the API.
	 * @var array
	 */
	protected $result = NULL;

	/**
	 * Determine if API has already been queried.
	 * @var bool
	 */
	protected $queried = FALSE;

	/**
	 * Names of known search engines.
	 * @var array
	 */
	public $names = [
		1 => 'AltaVista',
		2 => 'Ask',
		3 => 'Baidu',
		4 => 'Excite',
		5 => 'Google',
		6 => 'Looksmart',
		7 => 'Lycos',
		8 => 'MSN',
		9 => 'Yahoo',
		10 => 'Cuil',
		11 => 'InfoSeek',
	];

	/**
	 * Create a new instance.
	 * @param string $address
	 * @param string $key
	 */
	public function __construct($address, $key = NULL) {
		$this->setAddress($address);

		if(!$key) {
			$key = static::getDefaultKey();
		}

		$this->setKey($key);
	}

	/**
	 * Validate an API key.
	 * @param string $key
	 * @return bool
	 */
	public static function validateKey($key) {
		if(preg_match('/^[a-z]{12}$/', $key)) {
			return TRUE;
		}

		return FALSE;
	}

	/**
	 * Validate an IPv4 address.
	 * @param string $address
	 * @return bool
	 */
	public static function validateAddress($address) {
		if(filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE)) {
			return TRUE;
		}

		return FALSE;
	}

	/**
	 * Get the default API key.
	 * @return string|NULL
	 */
	public static function getDefaultKey() {
		return static::$defaultKey;
	}

	/**
	 * Set the default API key.
	 * @param $key
	 */
	public static function setDefaultKey($key) {
		if(!static::validateKey($key)) {
			throw new InvalidArgumentException('Default API key is invalid.');
		}

		static::$defaultKey = $key;
	}

	/**
	 * Reset the default API key.
	 */
	public static function unsetDefaultKey() {
		static::$defaultKey = NULL;
	}

	/**
	 * Get the API key.
	 * @return string|NULL
	 */
	public function getKey() {
		return $this->key;
	}

	/**
	 * Set the API key.
	 * @param string $key
	 */
	public function setKey($key) {
		if(!static::validateKey($key)) {
			throw new InvalidArgumentException('API key is invalid.');
		}

		$this->key = $key;
	}

	/**
	 * Get the IP address.
	 * @return string|NULL
	 */
	public function getAddress() {
		return $this->address;
	}

	/**
	 * Set the IP address.
	 * @param string $address
	 */
	public function setAddress($address) {
		if(!static::validateAddress($address)) {
			throw new InvalidArgumentException('IP address is invalid.');
		}

		if($address != $this->getAddress()) {
			$this->reset();
		}

		$this->address = $address;
	}

	/**
	 * Get the transformed API result.
	 * @param string $key
	 * @return array|int|NULL
	 */
	public function getResult($key = NULL) {
		$this->query();

		if(!is_null($key)) {
			return array_key_exists($key, $this->result)
				? $this->result[$key]
				: NULL;
		}

		return $this->result;
	}

	/**
	 * Indicate whether the IP address refers to a search engine or not.
	 * @param int $type
	 * @return bool
	 */
	public function isSearchEngine($type = NULL) {
		$this->query();

		if($this->getType() != static::TYPE_SEARCH_ENGINE) {
			return FALSE;
		}

		if(!is_null($type) && $type != $this->getThreat()) {
			return FALSE;
		}

		return TRUE;
	}

	/**
	 * Indicate whether the API address is known for suspicious behavior or not.
	 * @return bool
	 */
	public function isListed() {
		$this->query();
		return (bool) ($this->getType() > static::TYPE_SEARCH_ENGINE);
	}

	/**
	 * Indicate whether the IP address is suspicious or not.
	 * @return bool
	 */
	public function isSuspicious() {
		$this->query();
		return (bool) ($this->getType() & static::TYPE_SUSPICIOUS);
	}

	/**
	 * Indicate whether the IP address refers to a harvester or not.
	 * @return bool
	 */
	public function isHarvester() {
		$this->query();
		return (bool) ($this->getType() & static::TYPE_HARVESTER);
	}

	/**
	 * Indicate whether the IP address refers to a spammer or not.
	 * @return bool
	 */
	public function isSpammer() {
		$this->query();
		return (bool) ($this->getType() & static::TYPE_SPAMMER);
	}

	/**
	 * Get the IP's last activity in days.
	 * @return int|NULL
	 */
	public function getActivity() {
		$this->query();
		return $this->getResult('activity');
	}

	/**
	 * Get the IP's threat score.
	 * @return int
	 */
	public function getThreat() {
		$this->query();
		return $this->getResult('threat');
	}

	/**
	 * Get the IP's type.
	 * @return int
	 */
	public function getType() {
		$this->query();
		return $this->getResult('type');
	}

	/**
	 * Check if the IP was active within the given number of days.
	 * @param int $days
	 * @return bool
	 */
	public function isActive($days) {
		$this->query();
		return $days >= $this->getActivity();
	}

	/**
	 * Check if the IP's threat score is within in the given score.
	 * @param int $threat
	 * @return bool
	 */
	public function isThreat($threat) {
		$this->query();
		return $threat <= $this->getThreat();
	}

	/**
	 * Get the IP's search engine name if applicable.
	 * @return bool|FALSE
	 */
	public function getName() {
		$this->query();

		if(!$this->isSearchEngine()) {
			return FALSE;
		}

		$identifier = $this->getThreat();

		if(in_array($identifier, [static::CLIENT_UNKNOWN, static::CLIENT_OTHER])) {
			return FALSE;
		}

		return $this->names[$identifier];
	}

	/**
	 * Query the API for data and format the response.
	 * @param bool $force
	 * @return array|FALSE
	 */
	public function query($force = FALSE) {
		if($this->queried && !$force) {
			return $this->getResult();
		}

		# format address
		$host = $this->buildHost();

		# lookup address
		$result = $this->lookup($host);

		# set flag
		$this->queried = TRUE;

		if($result == $host) {
			return FALSE;
		}

		return $this->result = $this->formatResult($result);
	}

	/**
	 * Get host information via API call.
	 * @param string $host
	 * @return string
	 */
	protected function lookup($host) {
		return gethostbyname($host);
	}

	/**
	 * Build the host for the API call.
	 * @return string
	 */
	protected function buildHost() {

		# retrieve key
		$key = $this->getKey();

		# prepare address
		$address = $this->getAddress();
		$address = explode('.', $address);
		krsort($address);
		$address = implode('.', $address);

		# build hostname
		return implode('.', [
			$key,
			$address,
			static::API_HOST
		]);
	}

	/**
	 * Format the raw API result.
	 * @param string $result
	 * @return array
	 */
	protected function formatResult($result) {

		# split and ...
		$result = explode('.', $result);

		# ... structure result
		return [
			'activity' => (int) $result[1],
			'threat' => (int) $result[2],
			'type' => (int) $result[3],
		];
	}

	/**
	 * Reset the state of the object.
	 */
	protected function reset() {
		$this->result = NULL;
		$this->queried = FALSE;
	}
}
