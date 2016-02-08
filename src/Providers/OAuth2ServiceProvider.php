<?php

namespace Ephemeral\Providers;

use Ephemeral\OAuth2;
use Silex\ServiceProviderInterface;
use Silex\Application;

class OAuth2ServiceProvider implements ServiceProviderInterface
{

    public function register(Application $app)
    {
        // TODO: Implement register() method.
        $app['oauth2'] = $app->share(function ($app) {
            return new OAuth2($app);
        });
    }

    public function boot(Application $app)
    {
        // TODO: Implement boot() method.
    }
}