# iDEA Badge Tutorial

In this document we are going to go through the practical steps of creating your very own iDEA badge.

## About this guide

We assume you have a basic understanding of web technologies (HTTP, HTML, etc), a basic understanding of development tools such as text editors and the terminal, and a basic understanding of programming in PHP.

In this guide we will be using PHP, Heroku and Git.

## Prerequisites

Before we begin, you should already have your badge credentials:

* Client ID
* Client Secret

## Setting up a local development environment

###Install PHP

PHP already comes preinstalled

```
php -v
```

###Create a Git repository


###Install Composer

```
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php composer-setup.php
php -r "unlink('composer-setup.php');"
```

###Install Guzzle

yadda yadda

## Authenticating the user with Auth0


We'll now go through the steps involved in creating an `index.php` file to authenticate users when they land on your badge site.

When someone lands on your badge site, instead of serving any content, we immediately want to redirect them to Auth0 to check for their authorisation status.

Typically, the user will already be logged into the iDEA hub site, so they will already have a valid logged-in session with Auth0, which means that they won't be prompted to login again at Auth0, and will be _immediately_ redirected back to your badge site.

### Creating the page, step-by-step

The first thing you always need to do is open our `<?php` tag and call `session_start()` to start a new session (or resume an existing one).

> ####Sessions
>Sessions are a way of storing data between visits to a webpage, and passing data between pages on a website. The most common form of sessions are stored as cookies, which you are probably already familiar with.

```php
<?php

session_start();
```

Next, we need to generate a random state, to prevent against CSRF attacks against our new badge site.

> ####CSRF Attacks
> A Cross-Site Request Forgery (CSRF) attack involves an attacker exploiting the trust that a site has in a user's browser. The attacker typically embeds an HTML image tag (or malicious link) on a webpage (e.g. a public forum). When the victim's browser loads the "image" URL (which is actually a specially-crafted URL to perform an action on the user's behalf without their knowledge), it also sends the session cookies for that site if the user was already signed-in to that site.
> 
> The OAuth2 flow is vulnerable to CSRF attacks, because _____
> 
> In short, the use of a randomly-generated state ensures that the authorisation codes requested by one client aren't used maliciously by another.
> 
> For more information on the importance of the state parameter in OAuth2, see [this page](http://www.twobotechnologies.com/blog/2014/02/importance-of-state-in-oauth2.html).

There are various ways we can generate a random state, but one way of doing this which we show here is by generating a hash based on the current timestamp along with a random element, to create a random string like `c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2`.

```php
$state = hash('sha256', microtime(true) . rand());
```

Next, we simply store this state in our current session, so that we can validate it later. We store it under the key `oauth2_state`.

```php
$_SESSION['oauth2_state'] = $state;

```

Next, we need to build the authentication URL, to which the user is going to be redirected. The URL takes a fixed format of `https://idea.eu.auth0.com/i/oauth2/authorize` followed by a query string consisting of:

* `response_type` - the _response type_ that corresponds to the grant type we are using. In this case, we are building a server-side web application in PHP, so this should be set to `code`.
* `client_id` - your Auth0 client ID, which is unique to your badge site.
* `redirect_uri` - the URL to which the user should be redirected to, after completing the authentication with Auth0.
* `scope` - the _scope_ of the attributes that should be contained within the access token that will be issed. In this case, we are only interested in the default `openid` attributes (more on those later).
* `state` - the randomly state we generated earlier to protect against CSRF attacks. We need to send this to Auth0 with our request, so that Auth0 sends it back to us later in the process so we can be sure that the user intentionally authorized this request.

```php
$params = [
   'response_type' => 'code',
   'client_id' => '__YOUR__CLIENT__ID__',
   'redirect_uri' => 'https://contoso.com/auth/callback',
   'scope' => 'openid',
   'state' => $state
];

$authUrl = 'https://idea.eu.auth0.com/i/oauth2/authorize?' . http_build_query($params);
```

Next, we redirect the user to this URL, by rewriting the `Location` HTTP header (this is the standard mechanism in PHP to perform an HTTP 302 redirect):

```php
header("Location: $authUrl");
```


###Putting it all together

Having followed the above steps, you should now have the following code:

```php
<?php

session_start();

$state = hash('sha256', microtime(true) . rand());
$_SESSION['oauth2_state'] = $state;

$params = [
   'response_type' => 'code',
   'client_id' => '__YOUR__CLIENT__ID__',
   'redirect_uri' => 'https://contoso.com/auth/callback',
   'scope' => 'openid',
   'state' => $state
];

$authUrl = 'https://idea.eu.auth0.com/i/oauth2/authorize?' . http_build_query($params);

header("Location: $authUrl");
```

You can save this file as `index.php`.

##Exchange the authorization code for an access token

Once the user has finished authenticating with Auth0, they will then be redirected back to your badge site, at the `redirect_uri` you provided in your original redirect to Auth0.

The redirect back to your site will include two query string parameters in the URL:

* `state`, which should be the same value as the `state` value you randomly generated in the original redirect.
* `code`, which is an authorization code issued by Auth0, which will need to be exchanged for a proper access token to allow you to access protected iDEA resources (such as getting a user's profile and updating their badge progress).

###Creating the page, step by step

As before, we will now go through the code line-by-line of how you 

Just like before, we need to open a new PHP tag, and start (resume) the session (note that this does not start a new session if one already exists, rather it will resume the existing session that the user started in `index.php` earlier):

```php
<?php

session_start();
```

Next, we need to read the `state` and `code` parameters from the URL, and this can be done via the `$_GET` array in PHP:

```php
$state = $_GET['state'];
$code = $_GET['code'];
```

First, we need to check that the URL actually contains a `code` at all; if not, this would normally indicate that authentication failed:-

```php
if (!isset($code)) {
   exit('Failed to get an authorization code');
}
```
Next, we need to check that a `state` was sent back, and that the `state` is the same as the `oauth2_state` variable we stored in the session earlier in `index.php` (this is the protection against CSRF attacks):

```
if (isset($state) && $state !== $_SESSION['oauth2_state']) {
```

So if this check fails, then this might be due to a CSRF attack, so we want to immediately destroy the session, and exit.

```php
   session_destroy();
   exit('OAuth2 invalid state!');
}
```

If the check succeeds, then the program execution continues, and we can now be certain that we have a `code`, and we also have a valid `state`, so we can now proceed with exchanging our authorization code for an access token.

The process of exchanging the authorization code for an access token is done by making a `POST` HTTP call to Auth0, providing them with:

* `client_id` - the Client ID of our badge site
* `client_secret` - the Client Secret of our badge site (note that it is safe to include this parameter here, since this is being sent in a server-to-server call from your badge site server directly to Auth0, so it is never exposed to the user's browser)
* `redirect_uri` - must match the `redirect_uri` we set in our original request
* `code` - the code we received in the query string
* `grant_type` - the type of OAuth2 flow we are using (in this case as it is a server-side web application, we specify `authorization_code`)

There are various ways to make HTTP requests in PHP (most notably using cURL), however for readability and ease-of-use, we advise using [Guzzle](http://docs.guzzlephp.org/en/latest/), a popular open-source PHP HTTP client. If you followed the Getting Started section of this guide, Guzzle should already be installed, but if not please install it now before proceeding.

When using Guzzle, we first need to create a new HTTP client:-

```
$client = new \GuzzleHttp\Client();
```
We can now proceed with making a new request, in this case we specify it is a `POST` request, pass in the Auth0 token exchange URL, and set the `form_params` to the values described above.

`form_params` specifies that the data will be sent in `application/x-www-form-urlencoded` format.

```
$res = $client->request('POST', 'https://idea.eu.auth0.com/oauth/token', [
     'form_params' => [
          'client_id' => self::CLIENT_ID,
          'client_secret' => self::CLIENT_SECRET,
          'redirect_uri' => 'https://contoso.com/profile',
          'code' => $code,
          'grant_type' => 'authorization_code'
     ]
]);
```

We can then execute the call and get the response, 

```
$json = json_decode($res->getBody());
```

```
$_SESSION['oauth2_access_token'] = $json->access_token,
$_SESSION['oauth2_id_token'] = $json->id_token;

header('Location: /profile');
exit;
```

###Putting it all together

##Getting the user's profile information

##Creating a basic badge task
Some sort of 1+1=2 task

##Updating the user's profile (redeeming the badge)

##Testing your badge site locally

You can test your badge locally by opening a terminal at your badge site home directory, and run:

```
php -S localhost:3000
```

Which will start PHP's built-in web server on your local machine (`localhost`) on port 3000.

You can now open a browser at `http://localhost:3000` to visit your brand new badge site!

###Troubleshooting

####Wrong Client ID/Client Secret

####Wrong `redirect_uri`

##Deploying your badge site to Heroku
###Creating a Heroku account
###Creating a dyno
###Setting up git
This should probably go at the beginning
###Deploying

##Trying out your badge live

##Badge guidelines compliance

###Logout

Building the `logout.php` page.

###Handling errors

Redirect to `/error/generic`.

###Security
* Never expose the `access_token` or `id_token` to the user.
* Never share the `access_token` with a third-party application.
* Seek advice before sharing the `id_token` with third party applications.

##Next steps
###Understanding JWTs
###Doing cool stuff with the `id_token`
