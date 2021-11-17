
# OAuth2ClientService

This lib provides a base for integrating with [OAuth 2.0 / Laravel Passport](https://laravel.com/docs/8.x/passport) service providers.

[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](https://github.com/diegoagudo/OAuth2Client.js/blob/master/LICENSE)
[![Source Code](https://img.shields.io/badge/source-diegoagudo/OAuth2ClientService-blue.svg?style=flat-square)](https://github.com/diegoagudo/OAuth2ClientService)

---
This OAuth 2.0 client library will work with Laravel Passport provider that conforms to the OAuth 2.0 Authorization Framework.

## Requirements
* [Laravel](https://www.laravel.com)


## Usage

### Methods
| Method | Description  |
|--|--|
| getLoginUrl | Returns URL for login on Authorizer |
| getLogoutUrl | Returns URL for logout |
| handleLoginProviderCallback | Catch Token and Refresh token after login|

#### Responses samples
##### getLoginUrl
Replace your Login page to redirect to URL from *getLoginUrl*
```JS
http://host.from-laravel-passport.com/oauth/authorize?client_id=7&redirect_url=http%3A%2F%2Flocalhost%3A3005%2Fauth%2Fcallback&response_type=code&state=Hv05BLNDGKGsli9LfFYFOVWTlvZ5QG2u25icXlbioLqQJiMMnVU8ESQkeJy8Tu7ImTg7VufS1mTpWxvncWwCa3B0xcbfm005Y9UYDt24kVnr5Kq6kuBnI5tRyX6hulCNTrao8Woj6ANFrKi9hnNNErBuy4XTbFAMO3Fxk2Gx9bWB5vWOJlXzITQF1ijBoPXMPFx6lc1zQvfUycljyhhJ3s3tveCFYOtfM08ebXIDBTqymeGP80yYNvnPj3AfOrdD
```

##### getLogoutUrl
Replace your Logout page to redirect to URL from *getLogoutUrl*
```JS
http://host.from-laravel-passport.com/oauth/logout?client_id=7&redirect_url=http%3A%2F%2Flocalhost%3A3005%2F
```

#####  handleLoginProviderCallback
```PHP
(object) array(
 'token_type' => 'Bearer',
 'expires_in' => 1296000,
 'access_token' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiI3IiwianRpIjoiMjRkMmY3NWU2MzJlN2FkOWNkZDY2YmZiYTlmZDNiMWYzNjk5Y2NkNzU0Mzg0NDgxOTI5Y2U1MWVjNmRlZDE3NGUyODVjZDkxOTU3ZTI0YWMiLCJpYXQiOjE2MzcxNzM3NDEuMTY5NDk3LCJuYmYiOjE2MzcxNzM3NDEuMTY5NSwiZXhwIjoxNjM4NDY5NzQxLjE1MTY4NCwic3ViIjoiMSIsInNjb3BlcyI6W119.FRhkT2hjXqu-D3QIel9Z88iSuSag9mzoDu_WG9unV3wCi2J_itzXqwl6coVbmEMfQLL8lfmdJrydiiLTTYFooIX6AyD-GW3JWGkp0n7dBcrXxM1JZF5wJulrbNNvbK-pzDaoknAP-lwf_4A2qZxcDg8Uhyr7SzjDSjdqAwZ0am8tUbuuGbtiitzgykUq8_HD1I5qN7Dp9jr4sGyUclgoJf-gmVKjECCi_lkdEvdWeClJRJdlL6CP3CTE70kihzvo_7szSevou7m7GuA1V718r--XG10gFDfVTHXzFTzxG9F_FTFZEAWVfT1fbLFnCrCTvy0-dvvxJMuP2Est_LxKBwrMoDyPXGg-w-u8jeHfvF6fR5yGmJ1jwa7doCJKSMql0fGGG23Y5R8vQj3WXa_yrgxmk2kZI361JB-yEOk0lydTpT1o0_LysFlkQtimL6DrVpBiNuO5tDeqGfBSRzWyHDCCjdPJzieUMLxOn1s-kdqXae0E8LRfB24rHc95zFq73eNogzFAWjk-Sia9Lln_kU7q_hgoN5-FGGcFaxfo8WjlHsFHQ6yrcqVC7g_3FvjhtVdGHY46mqrlKJuepHN-bFjaRgIjBcK3-hcSXx5YaNvpdqvGemOeogtwT5uwsNmU4370QDYTbUgKYLKmew_m_veHisxFs10TeZ6O730zhM4',
 'refresh_token' => 'def50200f456118e74448789cae6f24b2e5438cea36281bf2960086012b4c4a0f84b1f2754b7168abca4fbd5fd9273e8dbd5c6d2117dc0c6cc1805b912901b276b6e629e1f3e00fcb6d8d96b4159136d389e2888312c050459f02a48cb48f442549ab6d73ca17bdc81c6abcc36f2a3d45b825ea0d3a68f48517c3d0b26a7ec5326eccd3e3f120317598a29ac8c998e85ac44ee990c0fdc53034fd55c18a31840698b48ef53eece3ccd7410c92a84542bea433c20ec8e6ee1d363ec9c6caa5e1a1590f0b3cf3646cd40a37d2989278f15df41df0b61f41b6b4d98b9fcc7b65dc684679bcbb520d4e06a4a892e9e024a7085ba8a01d71916a3e8893a99627d8ede378ebd35129d164a23862ed2e8ca3af6a2827d1b082d741e81abc648b72621475a24b2ca9960018573d202988394fe9e2ce6837b7d77ccafc26ef5c61a4ccf7f53bade304a78c4c1f1feb2268b76e0f1fe634b46264302b8be92488685eee17b03',
 'getUser' => 
(object) array(
   'id' => 1,
   'name' => 'diego',
   'email' => 'diego@agudo.eti.br',
   'email_verified_at' => NULL,
   'created_at' => '2021-10-28T14:40:09.000000Z',
   'updated_at' => '2021-10-28T14:40:09.000000Z',
),
)
```



### ENV
Add this lines in your ENV file. That's referrer information about your OAuth2 Server / Laravel Passport
```ENV
PASSPORT_HOST=host.from.laravel-passport.com
PASSPORT_CLIENT_ID=7  
PASSPORT_CLIENT_SECRET=Y3aJ1FOVQWY2MqcQfyz7dR7omU4jMZi97AReYbPJ  
PASSPORT_REDIRECT_URL=http://my.application.com/auth/callback  
PASSPORT_REDIRECT_URL_LOGOUT=http://my.application.com
```
### Routes 
You need add in your route file

#### GET /auth/callback
After Authorizer validate the user credentials, will redirect to callback URL with temp *Access Code*.
The `handleLoginProviderCallback` will request to Authorizer the *Token Access,* *Refresh Token* and *User Info*.
```PHP
Route::get('/auth/callback', function (\Illuminate\Http\Request $request) {
  $handleLoginProviderCallback = \App\Services\OAuth2ClientService::handleLoginProviderCallback();

  if(!isset($userToken) OR !$userToken)
      return redirect('/');

  // Check if user email exist in application
  $user = User::where(['email' => $userToken->getUser->email])->first();

  if($user){
      // user found, login
      Auth::login($users);
  } else {
      // user not found, create
      $user = User::create([
              /** params */
      ]);

      Auth::login($user);
  }

  return redirect('/');
});
```



## License

The OAuth2ClientService is open source software licensed under [the MIT license](https://opensource.org/licenses/MIT). See the [LICENSE](LICENSE.txt) file for more info.

