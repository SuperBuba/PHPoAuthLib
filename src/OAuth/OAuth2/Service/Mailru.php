<?php

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

class Mailru extends AbstractService
{

	public function __construct(
		CredentialsInterface $credentials,
		ClientInterface $httpClient,
		TokenStorageInterface $storage,
		$scopes = array(),
		UriInterface $baseApiUri = null
	) {
		parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri);

		if (null === $baseApiUri) {
			$this->baseApiUri = new Uri('http://www.appsmail.ru/platform/api');
		}
	}

	/**
	 * {@inheritdoc}
	 */
	public function getAuthorizationEndpoint()
	{
		return new Uri('https://connect.mail.ru/oauth/authorize');
	}

	/**
	 * {@inheritdoc}
	 */
	public function getAccessTokenEndpoint()
	{
		return new Uri('https://connect.mail.ru/oauth/token');
	}

	/**
	 * {@inheritdoc}
	 */
	protected function parseAccessTokenResponse($responseBody)
	{
		$data = json_decode($responseBody, true);

		if (null === $data || !is_array($data)) {
			throw new TokenResponseException('Unable to parse response.');
		} elseif (isset($data['error'])) {
			throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
		}

		$token = new StdOAuth2Token();
		$token->setAccessToken($data['access_token']);
		$token->setLifeTime($data['expires_in']);

		if (isset($data['refresh_token'])) {
			$token->setRefreshToken($data['refresh_token']);
			unset($data['refresh_token']);
		}

		unset($data['access_token']);
		unset($data['expires_in']);

		$token->setExtraParams($data);

		return $token;
	}

	/**
	 * {@inheritdoc}
	 */
	protected function getAuthorizationMethod()
	{
		return static::AUTHORIZATION_METHOD_QUERY_STRING;
	}
}
