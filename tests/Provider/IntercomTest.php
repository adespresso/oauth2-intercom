<?php

namespace Intercom\OAuth2\Client\Test\Provider;

use Ae\OAuth2\Client\Provider\Intercom;
use GuzzleHttp\ClientInterface;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class IntercomTest extends TestCase
{
    /** @var Intercom */
    protected $provider;
    protected $accessTokenResponse;

    protected function setUp()
    {
        $this->provider = new Intercom([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUri' => 'none',
        ]);

        $this->accessTokenResponse = json_encode([
            'access_token' => 'access_token',
            'token_type' => 'bearer',
            'uid' => '12345'
        ]);
    }

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl(['approval_prompt' => []]);
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayNotHasKey('approval_prompt', $query);
        $this->assertNotNull($this->provider->getState());
    }

    public function testGetAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $this->assertContains('https://app.intercom.io/oauth', $url);
    }

    public function testGetBaseAccessTokenUrl()
    {
        $url = $this->provider->getBaseAccessTokenUrl([]);
        $this->assertContains('https://api.intercom.io/auth/eagle/token', $url);
    }

    public function getResourceOwnerDetailsUrl()
    {
        $url = $this->provider->getBaseAccessTokenUrl('mock_token');
        $this->assertContains('https://api.intercom.io/me', $url);
    }

    public function testGetAccessToken()
    {
        $response = $this->getMockBuilder(ResponseInterface::class)->getMock();

        $response->expects($this->once())->method('getBody')->willReturn($this->accessTokenResponse);
        $response->expects($this->once())->method('getHeader')->willReturn(['content-type' => 'json']);
        $response->expects($this->once())->method('getStatusCode')->willReturn(200);

        $client = $this->getMockBuilder(ClientInterface::class)->getMock();
        $client->expects($this->once())->method('send')->willReturn($response);

        $this->provider->setHttpClient($client);

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $this->assertEquals('access_token', $token->getToken());
        $this->assertNull($token->getExpires());
        $this->assertNull($token->getRefreshToken());
        $this->assertNull($token->getResourceOwnerId());
    }

    public function testUserData()
    {
        $results = [
            'type' => 'admin',
            'id' => 42,
            'email' => 'fake@intercom.io',
            'name' => 'Fake User',
            'email_verified' => true,
            'app' => [
                'type' => 'app',
                'id_code' => 'sdu8d8e',
                'created_at' => 1528367877,
                'secure' => true,
                'avatar' => [
                    'type' => 'avatar',
                    'image_url' => 'http://fakeUrl'
                ]
            ]
        ];

        $response = $this->getMockBuilder(ResponseInterface::class)->getMock();
        $response->expects($this->once())->method('getBody')->willReturn($this->accessTokenResponse);
        $response->expects($this->once())->method('getHeader')->willReturn(['content-type' => 'json']);
        $response->expects($this->once())->method('getStatusCode')->willReturn(200);

        $userResponse = $this->getMockBuilder(ResponseInterface::class)->getMock();
        $userResponse->expects($this->once())->method('getBody')->willReturn(json_encode($results));
        $userResponse->expects($this->once())->method('getHeader')->willReturn(['content-type' => 'json']);
        $userResponse->expects($this->once())->method('getStatusCode')->willReturn(200);

        $client = $this->getMockBuilder(ClientInterface::class)->getMock();
        $client->expects($this->exactly(2))->method('send')->will(
            $this->onConsecutiveCalls( $response, $userResponse )
        );

        $this->provider->setHttpClient($client);

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $user = $this->provider->getResourceOwner($token);

        $this->assertEquals($results, $user->toArray());
        $this->assertEquals($results['id'], $user->getId());
        $this->assertEquals($results['email'], $user->getEmail());
        $this->assertEquals($results['name'], $user->getName());
        $this->assertEquals($results['avatar']['image_url'], $user->getAvatarUrl());
    }

    /**
     * @expectedException IdentityProviderException
     **/
    public function testExceptionThrownWhenErrorResponse()
    {
        $message = uniqid('', true);
        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage($message);

        $response = $this->getMockBuilder(ResponseInterface::class)->getMock();
        $response->expects($this->once())->method('getBody')->willReturn(sprintf('{"type":"error.list","request_id":"adsjhbasdjy712ye","errors":[{"code":"server_error","message":"%s"}]}', $message));
        $response->expects($this->once())->method('getHeader')->willReturn(['content-type' => 'json']);
        $response->expects($this->once())->method('getStatusCode')->willReturn(401);

        $client = $this->getMockBuilder(ClientInterface::class)->getMock();
        $client->expects($this->once())->method('send')->willReturn($response);

        $this->provider->setHttpClient($client);

        $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
    }
}