# iDEA Badge Tutorial

In this guide we are going to go through the practical steps of creating your very own iDEA badge.

This guide is intended as a "living document" which will be improved over time. If you notice anything which you feel could be improved, or any errors please contact us.

## 🤓 About this guide

We assume you have a basic understanding of, and familiarity with:

* General web technologies (HTTP, HTML, JSON, etc)
* Development tools such as text editors, Git and the terminal
* Programming in PHP

In this guide we will be using [PHP](http://www.php.net/), [Heroku](https://www.heroku.com/) and [Git](https://git-scm.com/) to build and deploy an iDEA badge from scratch.

## 🤷‍♂️ Prerequisites

Before you begin, you will need to apply for a Client ID and Client Secret for your badge site. You will need to contact iDEA to receive those credentials, and you will need to provide:

1. The name of your badge site
* The URL of your badge site
* The redirect (callback) URL for your badge site
* The logout URL for your badge site

If you will be following this guide and initially developing and testing your badge site locally, you can use the following URLs:

* Badge site URL: `http://localhost:8000`
* Redirect (callback) URL: `http://localhost:8000/callback.php`
* Logout URL: `http://localhost:8000/logout.php`

Please note that if you are intending to deploy to Heroku, you will need to provide updated URLs in due course.

Once you have provided these details you will then be issued with your badge credentials, consisting of:

* Client ID
* Client Secret

If you wish to deploy your badge site to Heroku, you will also need to register for a free Heroku account. 

## 💻 Setting up a local development environment

### Install PHP & Web Server

#### macOS/Linux Users

PHP and Apache already come preinstalled on macOS and some Linux distributions. To check you have PHP pre-installed, run the following from a terminal:

```
php -v
```

If you don't have PHP installed or it is outdated then you should install the latest version of PHP via [Homebrew](https://brew.sh/).

#### Windows Users

The easiest way to get setup with Apache & PHP on Windows is to install [WampServer](http://www.wampserver.com/en/).

### Create a directory to hold your badge site

You should create a new directory (folder) on your machine to hold your badge site. We'll refer to this in the guide as your badge site root directory.

### Create a Git repository

To start with, you will need to create a new Git repository on your computer. A Git repository will provide you with the ability to commit your work, rollback to previous versions of your code, to collaborate with our developers, and to deploy your code to other cloud services like Heroku.

>#### GitHub
>
>You may wish to set yourself up with an account on [GitHub](https://www.github.com/), a popular cloud-based Git hosting platform. This will allow other developers (either in your private team, or on the web) to view your code, and fork it or contribute their own changes or updates. It also provides a more friendly GUI for managing your repositories. This guide doesn't require the use of GitHub, so we'll only create a local repository, and push it directly to Heroku.

To create a new Git repository, simply run the following terminal command from your badge site root directory:

`git init`

### Install Composer

[Composer](https://getcomposer.org/) is a dependency manager for PHP. It allows the simple installation and management of third-party PHP libraries on which your project depends.

To install Composer, run the following in your terminal:

```
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php composer-setup.php
php -r "unlink('composer-setup.php');"
```

### Install Guzzle

You can now install [Guzzle](https://guzzle3.readthedocs.io/) using Composer. To install, first you need to create a new `composer.json` file in your badge site root directory, with the following contents:

```
{
    "require": {
        "guzzlehttp/guzzle": "~6.0"
    }
}
```

You can then run `composer install` from the terminal which will install Guzzle for you, along with any associated dependencies.

### Setting up environment variables

When creating our badge site we're going to need to handle various variables specific to our project and environment.

> #### Environment Variables
> Environment variables are a set of system-wide global variables that can be read/written by any application running on your machine. You may already be familiar with `PATH` which is an OS-specific environment variable consisting of a set of paths which are checked when a user types a command in the terminal without providing the full path.

We are going to setup some environment variables which will hold our client ID, client secret and callback (redirect) URL. These variables can then be accessed by our PHP code.

Adding environment variables depends on your OS. On macOS you can add the following to your `~/.bash_profile` file:

```
export GENIUS_BADGE_CLIENT_ID="__your_client_id__"
export GENIUS_BADGE_CLIENT_SECRET="__your_client_secret__"
export GENIUS_BADGE_REDIRECT_URI="http://localhost:8000/callback.php"
```

Windows users can follow [this guide](http://www.computerhope.com/issues/ch000549.htm) to adding environment variables.

> #### Environments and Security
> You might be wondering why we don't simply hard-code these values into our script, or store them as constants in our PHP code. There are two important reasons for this:
>
> 1. These values (our redirect URL in particular) are *environment specific* - our callback URL when running in our local environment will be different when we deploy on Heroku, so it makes sense to set these values at the system level, rather than within our code.
> 
> 2. For security reasons, you should never commit credentials such as your Client Secret to your Git repository, as this may not be secure. Putting your Client Secret only on your local machine and deployment server ensures that you have very tight control over who has visibility of those credentials.

This now completes your local development environment setup, and you are ready to start coding!

## 🔑 Authenticating the user with Auth0

We'll now go through the steps involved in creating an `index.php` file to authenticate users when they land on your badge site.

When someone lands on your badge site, instead of serving any content (i.e. your badge), we first need to redirect them to Auth0 to check for their authorisation status.

Typically, when originating from the iDEA hub site, the user will already be logged into iDEA, so they will already have a valid logged-in session with Auth0, which means that they won't be prompted to login again at Auth0, and will be _immediately_ redirected back to your badge site.

### Creating the page, step-by-step

The first thing you always need to do is open our `<?php` tag and call `session_start()` to start a new session (or resume an existing one).

> #### Sessions
>Sessions are a way of storing data between visits to a webpage, and passing data between pages on a website. The most common form of sessions are stored as cookies, which you are probably already familiar with.

```php
<?php

session_start();
```

Next, we need to generate a random "state" identifier, to prevent against CSRF attacks against our new badge site.

> #### CSRF Attacks
> A Cross-Site Request Forgery (CSRF) attack involves an attacker exploiting the trust that a site has in a user's browser. The attacker typically embeds an HTML image tag (or malicious link) on a webpage (e.g. a public forum). When the victim's browser loads the "image" URL (which is actually a specially-crafted URL to perform an action on the user's behalf without their knowledge), it also sends the session cookies for that site if the user was already signed-in to that site.
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
   'client_id' => getenv('GENIUS_BADGE_CLIENT_ID'),
   'redirect_uri' => getenv('GENIUS_BADGE_REDIRECT_URI'),
   'scope' => 'openid',
   'state' => $state
];

$authUrl = 'https://idea.eu.auth0.com/i/oauth2/authorize?' . http_build_query($params);
```

Next, we redirect the user to this URL, by rewriting the `Location` HTTP header (this is the standard mechanism in PHP to perform an HTTP 302 redirect):

```php
header("Location: $authUrl");
```

### Putting it all together

Having followed the above steps, you should now have the following code in your `index.php` file:

```php
<?php

session_start();

$state = hash('sha256', microtime(true) . rand());
$_SESSION['oauth2_state'] = $state;

$params = [
   'response_type' => 'code',
   'client_id' => getenv('GENIUS_BADGE_CLIENT_ID'),
   'redirect_uri' => getenv('GENIUS_BADGE_REDIRECT_URI'),
   'scope' => 'openid',
   'state' => $state
];

$authUrl = 'https://idea.eu.auth0.com/i/oauth2/authorize?' . http_build_query($params);

header("Location: $authUrl");
```

You can save this file as `index.php`, and are ready to proceed with the next step of the project.

## ♻️ Exchange the authorization code for an access token

Once the user has finished authenticating with Auth0, they will then be redirected back to your badge site, at the `redirect_uri` you provided in your original redirect to Auth0.

The redirect back to your site will include two query string parameters in the URL:

* `state`, which should be the same value as the `state` value you randomly generated in the original redirect.
* `code`, which is an authorization code issued by Auth0, which will need to be exchanged for a proper access token to allow you to access protected iDEA resources (such as getting a user's profile and updating their badge progress).

We will now build the page that the user should be returned to, which we will call `callback.php`.

### Creating the page, step by step

As before, we will now go through the code line-by-line of how the page is built up.

Just as before, we need to start by opening a new PHP tag and going straight into PHP. On this page, we're going to be using Guzzle which is a Composer dependency, so we need to include the `vendor/autoload.php` which will [autoload](https://getcomposer.org/doc/01-basic-usage.md#autoloading) Guzzle for us:

```php
<?php

require 'vendor/autoload.php';
```

We also need to resume the session by calling `session_start()` (note that despite the name, this does not start a new session if one already exists, rather it will resume the existing session that the user started in `index.php` earlier):

```php
session_start();
```

Next, we need to read the `state` and `code` parameters from the URL:

```php
$state = $_GET['state'];
$code = $_GET['code'];
```

First, we need to check that the URL actually contains a `code` at all; if not, this would normally indicate that authentication failed for some reason:

```php
if (!isset($code)) {
   exit('Failed to get an authorization code');
}
```
Next, we need to check that a `state` was sent back, and that the `state` is the same as the `oauth2_state` variable we stored in the session earlier in `index.php` (this is the protection against CSRF attacks):

```php
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

There are various ways to make HTTP requests in PHP (for example, using cURL, which you may be familiar with), however for simplicity and ease-of-use, we will be using [Guzzle](http://docs.guzzlephp.org/en/latest/), a popular open-source PHP HTTP client. If you followed the Getting Started section of this guide, Guzzle should already be installed, but if not please install it now before proceeding.

When using Guzzle, we first need to create a new HTTP client:-

```php
$client = new \GuzzleHttp\Client();
```
We can now proceed with making a new request, in this case we specify it is a `POST` request, pass in the Auth0 token exchange URL, and set the `form_params` to the values described above.

>#### Form encoding
>Using `form_params` in Guzzle automatically specifies that the data will be sent in `application/x-www-form-urlencoded` format.

```php
$res = $client->request('POST', 'https://idea.eu.auth0.com/oauth/token', [
     'form_params' => [
          'client_id' => getenv('GENIUS_BADGE_CLIENT_ID'),
          'client_secret' => getenv('GENIUS_BADGE_CLIENT_SECRET'),
          'redirect_uri' => getenv('GENIUS_BADGE_REDIRECT_URI'),
          'code' => $code,
          'grant_type' => 'authorization_code'
     ]
]);
```

We can then execute the call and get the response, which we can immediately decode to JSON:

```php
$json = json_decode($res->getBody());
```

We can now extract the `acccess_token` and `id_token` from the JSON response, and store it in the user's session:

```php
$_SESSION['oauth2_access_token'] = $json->access_token;
$_SESSION['oauth2_id_token'] = $json->id_token;
```
With that, we are now done, so we can now redirect the user straight to our badge page:

```php
header('Location: badge.php');
```

### Putting it all together

Having followed the above steps, you should now have the following code in your `callback.php` file:

```php
<?php

require 'vendor/autoload.php';

session_start();

$state = $_GET['state'];
$code = $_GET['code'];

if (!isset($code)) {
   exit('Failed to get an authorization code');
}

if (isset($state) && $state !== $_SESSION['oauth2_state']) {
	session_destroy();
	exit('OAuth2 invalid state!');
}

$client = new \GuzzleHttp\Client();

$res = $client->request('POST', 'https://idea.eu.auth0.com/oauth/token', [
     'form_params' => [
          'client_id' => getenv('GENIUS_BADGE_CLIENT_ID'),
          'client_secret' => getenv('GENIUS_BADGE_CLIENT_SECRET'),
          'redirect_uri' => getenv('GENIUS_BADGE_REDIRECT_URI'),
          'code' => $code,
          'grant_type' => 'authorization_code'
     ]
]);

$json = json_decode($res->getBody());

$_SESSION['oauth2_access_token'] = $json->access_token;
$_SESSION['oauth2_id_token'] = $json->id_token;

header('Location: badge.php');
```

With the authentication process now completed, we now have an `access_token` which we can use to perform actions on the user's behalf on the iDEA REST API, for example getting the user's profile information, or posting a badge result.

We are now redirected to `badge.php`, and with the authentication out of the way, we  are finally ready to begin building the badge content itself!

## 👤 Getting the user's profile information

Many badge sites will want to obtain profile information for a user, so that their experience can be customised on your site with their name and avatar, for example. A user's profile can be accessed via the iDEA REST API.

We'll call this file `badge.php`.

> For security and privacy reasons, iDEA only exposes minimal profile information to badge sites. You can only access the user's first name, and their profile image avatar.

Using Guzzle, we can obtain the user's profile information as follows.

Start by requiring the composer `autoload.php` file and starting the session, as before:

```php
<?php

require 'vendor/autoload.php';

session_start();
```

Next, create a new Guzzle client as before:

```php
$client = new \GuzzleHttp\Client();
```

We now want to create an HTTP `GET` request on `https://idea.org.uk/api/user` to get the user's profile info. In order to authenticate ourselves and tell the server which user we want to obtain the profile for, we need to pass the `access_token` as a bearer token in an `Authorization` header in the HTTP request. This header takes the format: `Authorization: Bearer __YOUR_TOKEN_HERE__`.

We can now create the HTTP request and specify the header:

```php
$res = $client->request('GET', 'https://idea.org.uk/api/user', [
	'http_errors' => false,
	'headers' => [
		'Authorization' => 'Bearer ' . $_SESSION['oauth2_access_token']
	]
]);
```

We can now get the body of the response, decode it as JSON, and store it in a `$user` variable so we can use it in our HTML:

```php
$user = json_decode($res->getBody());
```

Now that we have the user object, we can start writing the HTML of our webpage itself, so we can now close the PHP tag:

```php
?>
```

Finally, its time to write some HTML to render the badge page itself. We're going to keep things very simple and just create a basic profile information page:

```html
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>Genius Badge</title>
</head>
<body>
	<h1>Welcome, <?=$user->name?></h1>
	<p>
		<img src="<?=$user->image_url?>" alt="Profile avatar image">
	</p>
</body>
</html>
```
>#### PHP `<?=` tag
>If you aren't familiar with the `<?= $var ?>` tag, it is simply shorthand for `<?php echo $var; ?>`. It's more readable, and saves you some typing!

This page has an `<h1>` header tag which echoes the user's name, and an `<img>` tag which contains the user's profile (avatar) image.

## 🔨 Creating a basic badge task

Our badge site is going to be incredibly simple and easy: all the user has to do is a click a link saying "I Am A Genius" to complete the badge, and be awarded their points.

Let's add this link to our existing `badge.php` site, as an additional `<p>` tag underneath the profile avatar image. Our existing `<body>` code from earlier should now look like this:

```php
<body>
	<h1>Welcome, <?=$user->name?></h1>
	<p>
		<img src="<?=$user->image_url?>" alt="Profile avatar image">
	</p>
	<p>
		Are you a genius? <a href="badge-completed.php">Click here!</a>
	</p>
</body>
```

When the user clicks the link, they will be taken to `badge-completed.php` which will handle the process of awarding them with the points via the iDEA REST API.

#### Putting it all together

You should now have the following in your `badge.php` file:

```php
<?php

	require 'vendor/autoload.php';
	
	session_start();
	
	$client = new \GuzzleHttp\Client();
	$res = $client->request('GET', 'https://idea.org.uk/api/user', [
		'http_errors' => false,
		'headers' => [
			'Authorization' => 'Bearer ' . $_SESSION['oauth2_access_token']
		]
	]);
	
	$user = json_decode($res->getBody());

?>

<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>Genius Badge</title>
</head>
<body>
	<h1>Welcome, <?=$user->name?></h1>
	<p>
		<img src="<?=$user->image_url?>" alt="Profile avatar image">
	</p>
	<p>
		Are you a genius? <a href="badge-completed.php">Click here!</a>
	</p>
</body>
</html>
```

## 🏆 Updating the user's profile (redeeming the badge)

We are now going to build our `badge_completed.php` page which is accessed when the user has successfuly completed the badge.

>#### Completion validation
>
>Clearly, this example has been for illustration only: in reality, your badge should in some way validate that the user has completed the badge. For example, this would usually be by way of a quiz or other exercises and then validating the answers, to confirm that the user has learnt the required information/completed the necessary exercises in order to deserve their points.

A badge can be redeemed by making an HTTP `POST` request to `https://idea.org.uk/api/result`. As with the `/api/user` call, we need to pass in the access token as a bearer token in an HTTP `Authorization` header. The API will validate the access token and determine which badge should be redeemed.

We start by including the Composer `autoload.php` file, starting the session, and creating a Guzzle HTTP client, as before:

```php
<?php

require 'vendor/autoload.php';

session_start();

$client = new \GuzzleHttp\Client();
```

We can now make a `POST` request to the iDEA REST API. We also need to pass in a JSON body, which contains a single key `result` with a value of either `pass` (if the user successfully passed the badge) or `fail` (if the user failed the badge):

```php
$res = $client->request('POST', 'https://idea.org.uk/api/result', [
	'http_errors' => false,
	'headers' => [
		'Authorization' => 'Bearer ' . $_SESSION['oauth2_access_token']
	],
	'json' => [
		'result' => 'pass', // Or fail, if the badge was failed
	]
]);
```

> #### How iDEA treates passes and failures
> 
> If the user has _passed_ the badge, they will be awarded points and the badge will show as "completed" in their profile.
> 
> If the user _failed_ the badge, then they will not be awarded any points, the badge will not show as completed, and they will be given further opportunities to retry the badge.
> 
> Even if the user failed the badge, you must still always call the `/api/result` endpoint to let the hub site know the outcome of the badge attempt. At this point in time, users are allowed unlimited retries of badges, but it is still important for iDEA to be able to record the number of attempts made by a user for each badge.

Next, you should check the API response, which will tell you whether or not the badge was redeemed successfully:

```php
$response = json_decode($res->getBody());
```

If redeemed successfully, the API will also give you a `return_url` which you should redirect the user to, to return them to the iDEA hub site.

With the badge redeemed, you are now ready to log the user out, and return them to the iDEA at the `return_url` specified.

#### Putting it all together

You should now have the following in your `badge-completed.php` file:

```php
<?php

require 'vendor/autoload.php';

session_start();

$client = new \GuzzleHttp\Client();

$res = $client->request('POST', 'https://idea.org.uk/api/result', [
	'http_errors' => false,
	'headers' => [
		'Authorization' => 'Bearer ' . $_SESSION['oauth2_access_token']
	],
	'json' => [
		'result' => 'pass', // Or fail, if the badge was failed
	]
]);

$response = json_decode($res->getBody());

header("Location: logout.php?return_url=$return_url");
```

## 👋 Logging out

Before returning the user to iDEA, you should log them out from your badge site. We'll need a new file called `logout.php` to facilitate this.

>#### Single Sign-Out
>Although logging out the user before returning them to iDEA is technically not essential, it is part of the iDEA Badge Technical Guidelines to do so.
>
>The reason for this is that if your badge site does not log the user out, the user's session on your site may last longer than their session on the hub site. This could result in a situation where the user is logged out from the hub site, but remains signed in your badge site without their knowledge, and represents a security risk.
>
>Therefore, whenever your badge site returns the user to the hub site (whether by clicking a back button, or upon completion of the badge), you should always destroy their session.
>
>Also, you should ensure that your session expiry is less than XXXXXX (TODO: the hub site session expiry) to further mitigate this.

In PHP, ending a session is as simple as calling `session_destroy()`, _however_ we want to do something slightly more complex here, which is to log the user out and then send them on to the `return_url` (if we have one).

This means that we need to follow these steps:

1. Pass the `return_url` to the `logout.php` page from `badge_completed.php`.
2. Call `session_destroy()` to destroy the user's session.
3. Redirect to the `return_url` using `header('Location: ______');` )like we did when redirecting to Auth0).

So first we need to update our `badge_completed.php` page to redirect to `logout.php` and to pass the `redirect_url` in the URL query string. You should add the following line of code to the end of `logout.php`:

```php
header("Location: logout.php?return_url=$return_url");
```

Next, in your new `logout.php` you need to open the PHP tag and first call `session_start()`, before calling `session_destroy()` (although it may seem counter-intuitive to start the session and then immediately destroy it, this is required).

```php
<?php

session_start();

session_destroy();
```

Next, we want to get the `return_url` from the URL querystring, so we can access it in the `$_GET` array. If there is no `return_url` provided, we can default to `https://www.idea.org.uk/` which is the hub site homepage:

```php
$return_url = $_GET['return_url'] ?? 'https://www.idea.org.uk/';
```

>#### `??` operator
>The `??` is the null coalescing operator, which is available in PHP 7.0+. If you're using an earlier version of PHP you would need to do `$return_url = $_GET['return_url'] != NULL ? $_GET['return_url'] : 'https://www.idea.org.uk/';`

Finally, we can redirect to the `return_uri`:

```php
header("Location: $return_url");
```

#### Putting it all together

You should now have the following in your `logout.php`:

```php
<?php

session_start();

session_destroy();

$return_url = $_GET['return_url'] ?? 'https://www.idea.org.uk/';

header("Location: $return_url");
```

At last, we are done! The user's badge journey is complete and they have been returned to the iDEA hub site.

## 🤔 Testing your badge site locally

You can test your badge locally by opening a terminal at your badge site home directory, and run:

```
php -S localhost:8000
```

Which will start PHP's built-in web server on your local machine (`localhost`) on port 8000. Make sure this port matches the port number in the Callback URL that you registered for your badge site at the outset.

You can now open a browser at `http://localhost:8000` to visit your brand new badge site!

## 👍 Commit your code

If you haven't been committing your code to Git as you've been going along, then now that you have everything working you should make sure you commit your code before proceeding further.

Firstly, you should create a `.gitignore` file and add some exclusions for files which we don't want to include in our repository:

* `.DS_Store` files are created by macOS and stores custom attributes of its containing folder; this is unnecessary clutter and doesn't need to be part of your repository.
* `composer.phar` is the executable for Composer itself. This is not part of your project, so shouldn't be included in the repository to save space and avoid version conflicts with other developers.
* `/vendor` contains your Composer packages. It is considered bad practice to include compiled dependencies with your project, so you should omit this folder from your repository (other developers can use composer to fetch and manage the dependencies themselves from your `composer.json`.

Your `.gitignore` file should therefore look like this:

```
.DS_Store
composer.phar
/vendor
```

You need should stage all your files:

`git add .`

You can then commit your files, with a message:

`git commit -m "It works!"`

## 🚀 Deploying your badge site to Heroku 

### Creating a Heroku account

If you haven't already, you should now sign up for a free Heroku account at [www.heroku.com]().

### Installing the Heroku CLI

Follow the guide for [Getting Started on Heroku with PHP](https://devcenter.heroku.com/articles/getting-started-with-php#set-up). This involves:

1. Downloading and istalling the Heroku CLI which will allow you to use Heroku from the terminal on your local machine.


2. Running `heroku login` in your badge site root directory to login to the Heroku CLI with your email address and Heroku password.

### Creating a new Heroku app

>### Heroku apps and dynos
>
>A Heroku "app" is an application which runs on the Heroku platform, in this case in PHP. An app can run on one or more "dynos" - don't let the terminology confuse you, to keep things simple at this point you can just think of an app as a website.

To create your app, simply run `heroku create` which will create a new (empty) Heroku app for you, with a random name:

```
$ heroku create
Creating app... done, ⬢ arcane-brook-77567
https://arcane-brook-77567.herokuapp.com/ | https://git.heroku.com/arcane-brook-77567.git
```

As you can see Heroku has generated a random name for our app (in this case `arcane-brook-77567`) and has also generated a website URL for us (https://arcane-brook-77567.herokuapp.com/) and a Git remote (https://git.heroku.com/arcane-brook-77567.git).

If you visit the website (which you can do conveniently from the terminal using `heroku open`), you'll see a default home page ("Welcome to your new app!").

### Push your code

Your app doesn't have any code pushed to it yet, so to get more than just the default home page, you're going to need to upload your code. If you have used web hosting before then you might have used FTP to manually upload your HTML/PHP to your web server. Heroku is a bit more advanced than that and will do automatic deployments via your Git repository for you, so it very conveniently integrates directly into your Git workflow.

The neat thing about `heroku create` is that not only did it create a new app on the Heroku service, it also create a new Git [remote](https://git-scm.com/book/en/v2/Git-Basics-Working-with-Remotes) called `heroku` in your repository, preconfigured with the Git remote address above.

You can now push directly to this remote using:

`git push heroku master`

You'll now see a load of text whizzing past the screen as Git uploads your code to the remote, and Heroku now unpacks it, analyses your project, installs any dependencies, and prepares your environment.

### Setting environment variables

Before we can run your badge site on Heroku, we also need to setup the environment variables on Heroku.

The Heroku CLI provides a [convenient set of `config` commands](https://devcenter.heroku.com/articles/config-vars) which can be used to set, get and unset your environment variables.

To set your environment variables, run the following:

```
heroku config:set GENIUS_BADGE_CLIENT_ID=__your_client_id__
heroku config:set GENIUS_BADGE_CLIENT_SECRET=__your_client_secret__
heroku config:set GENIUS_BADGE_REDIRECT_URI=http://__your_app_name__.herokuapp.com/callback.php
```

**IMPORTANT:** Notice that your redirect URI has now changed to point to your *.herokuapp.com URL instead of localhost. You now need to contact iDEA and get this URL added to your list of allowed callback URLs, otherwise you will get a "Callback URL mismatch" error from Auth0.

## 🤞 Trying out your badge live

Once your new callback URL has been added to your Auth0 client, you are ready to now try out your badge live on Heroku.

You can either navigate to your Heroku app URL, or type `heroku open` from your badge site root directory to open your site in your default browser.

If you were already logged into the iDEA hub site, you should now find you are immediately automatically logged into your new badge site. If you weren't logged in to iDEA, you will be prompted by Auth0 to login first (visitors to your badge site generally won't have to login like this, as they'll already have a valid user session with the hub site so will skip the login step).

You can click the link on the page to award yourself the points, and will be redirected back to the iDEA hub site.

## 🎉 Congratulations!

**You have successfully setup a local development environment, built your own badge site in PHP, tested it lcoally and deployed it to Heroku for production.**