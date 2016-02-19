<?php

namespace Ephemeral;

use Guzzle\Http\Client;
use Guzzle\Http\Exception\ClientErrorResponseException;
use Guzzle\Http\Message\RequestInterface;
use Silex\Application;


class OAuth2 {

    protected $client;
    protected $app;
    protected $token;

    public function __construct(Application $app) {
        $this->app = $app;
        $this->client = new Client();
        $this->client->setBaseUrl($this->app['oauth2.hostname']);
    }

    //first check the header
    //Then check for an access_token on the request
    //Finally check the session
    public function token($req = null)
    {
        $token_info = $this->app['session']->get('token_info');
        if (is_array($token_info) && array_key_exists('access_token', $token_info)) {
            return $token_info['access_token'];
        }
        if (! null == $this->token) {
            return $this->token;
        }

        if (!is_null($req)) {
            // We've been passed a request
            $token_info = $req->headers->get('Authorization');
            if (strpos($token_info, 'Bearer ') === 0) {
                list(,$token_info) = explode(' ', $token_info);
                $this->token = $token_info;
                return $token_info;
            } else {
                $token_info = $req->get('access_token');
                if (!is_null($token_info)) {
                    $this->token = $token_info;
                    return $token_info;
                }
            }
        }
        return null;
    }

    public function getAccessToken($grant_type='client_credentials', $username='', $password='', $scope='', $response_type='', $refresh_token = '')
    {
        $params = [];
        foreach (["grant_type","username","password","scope","response_type","refresh_token"] as $key) {
            if ($$key != '') $params[$key] = $$key;
        }
        $request = $this->client->post('/oauth2/accessToken', array('exceptions' => false), $params);
        $request->setAuth($this->app['oauth2.client_id'], $this->app['oauth2.client_secret']);
        $response = $this->sendOAuth($request);

        return $response;
    }

    public function sendOAuth(RequestInterface $request)
    {
        try {
            $response = $request->send();
        } catch (ClientErrorResponseException $e) {
            return ["Error" => "Error:" . $e->getMessage()];
        }
        $return = json_decode($response->getBody(),true);
        if (array_key_exists("expires_in", $return)) {
            $return["expires_at"] = (integer) (date("U") + $return["expires_in"]);
        }
        return $return;
    }

    public function checkOauthException() {
        return null;
    }


    public function refreshToken() {
        $token_info = $this->app['session']->get("token_info");
        if (!is_array($token_info)) $token_info = [];
        if (array_key_exists("refresh_token", $token_info)) {
            if ((int) date("U") > $token_info["expires_at"] - 30){
                // either expired or about to expire refresh it
                $token_info = $this->getAccessToken('refresh_token', '', '', '', '', $token_info["refresh_token"]);
                $this->app['session']->set("token_info", $token_info);
                return;
            } else {
                // not expired roll with it.
                return;
            }
        }
        // Not a user token get a fresh one
        $token_info = $this->getAccessToken($grant_type = 'client_credentials');
        $this->app['session']->set("token_info", $token_info);
        return;
    }


    public function verifyToken($token) {
        $params = [ "access_token" => $token];
        $request = $this->client->post('/oauth2/verify', array('exceptions' => false), $params);
        $response = $this->sendOAuth($request);
        return $response;
    }

    public function checkAccess(\Symfony\Component\HttpFoundation\Request $request, \Silex\Application $app) {
        $app['token'] = $this->token($request);
        if ($app['token'] == null) {
            $app->abort(401, "Unauthorized");
        } else {
            $tmp = $this->verifyToken($app['token']);
            if (array_key_exists("authorized", $tmp)) {
                if ($tmp["authorized"] != true) {
                    $app->abort(401, "Unauthorized");
                }
            } else {
                $app->abort(401, "Unauthorized");
            }
        }
    }

    public function getOAuthUser(\Symfony\Component\HttpFoundation\Request $request, \Silex\Application $app)
    {
        $request = $this->client->get('/oauth2/tokenUser', array('exceptions' => false));
        $request->addHeader('Authorization', 'Bearer ' . $this->token());
        $response = $this->sendOAuth($request);
        return $response;
    }
}