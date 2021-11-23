<?php

namespace App\Services;

use App\Http\Requests\Request;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Http\Client\RequestException;
use Session;

/**
 * OAuth2ClientService
 */
class OAuth2ClientService
{
    const URL_AUTHORIZE = '%s://%s/oauth/authorize?%s';
    const URL_LOGOUT    = '%s://%s/oauth/logout?%s';
    const URL_TOKEN     = '%s://%s/oauth/token';
    const URL_USER_INFO = '%s://%s/api/user';
    const SESSION_CODE_STATE = 'oauth2_state';
    const SESSION_CHALLENGE_PUBLIC = 'oauth2_code_public';
    const SESSION_CHALLENGE_PRIVATE = 'oauth2_code_private';
    const CODE_STATE_SEPARATOR = '.';
    const CODE_CHALLENGE_METHOD = 'S256';

    /**
     * getLoginUrl
     * Retorna a URL de login do Autorizador
     *
     * @return String
     */
    public static function getLoginUrl():String {
        return sprintf(self::URL_AUTHORIZE,
            self::getHttpProcol(),
            ENV('PASSPORT_HOST'),
            http_build_query([
                'client_id' => ENV('PASSPORT_CLIENT_ID'),
                'redirect_url' => ENV('PASSPORT_REDIRECT_URL'),
                'response_type' => 'code',
                'state' => self::codeStateGenerator(),
                'code_challenge' => self::codeChallengeGenerator(),
                'code_challenge_method' => self::CODE_CHALLENGE_METHOD,
            ])
        );
    }


    /**
     * getLogoutUrl
     * Retorna a URL de logout
     *
     * @return String
     */
    public static function getLogoutUrl():String {
        return sprintf(self::URL_LOGOUT,
            self::getHttpProcol(),
            ENV('PASSPORT_HOST'),
            http_build_query([
                'client_id' => ENV('PASSPORT_CLIENT_ID'),
                'redirect_url' => ENV('PASSPORT_REDIRECT_URL_LOGOUT')
            ])
        );
    }


    /**
     * handleLoginProviderCallback
     * Recebe o código de autorização e solicita a token de acesso
     *
     * @return object
     * @throws \Exception
     */
    public static function handleLoginProviderCallback():Object {
        try {
            $code  = request()->input('code') ?? null;
            $state = request()->input('state') ?? null;

            self::validateCodeState($state);

            $tokenUrl = sprintf(self::URL_TOKEN,
                self::getHttpProcol(),
                ENV('PASSPORT_HOST'));

            try {
                $response = Http::post($tokenUrl, [
                    'grant_type' => 'authorization_code',
                    'client_id' => ENV('PASSPORT_CLIENT_ID'),
                    'client_secret' => ENV('PASSPORT_CLIENT_SECRET'),
                    'redirect_url' => ENV('PASSPORT_REDIRECT_URI'),
                    'code_verifier' => Session::get(self::SESSION_CHALLENGE_PRIVATE),
                    'code' => $code
                ])->object();

                if(isset($response->error))
                    throw new \RequestException($result->error_description??'Unknow error.');

                if(!isset($response->access_token) OR !isset($response->refresh_token))
                    throw new \RequestException('Access Token not found.');

                $response->getUser = self::getUser($response->access_token);

                return $response;
            } catch (RequestException $e) {
                throw new \RequestException($e->getMessage());
            }
        } catch(\Exception $e) {
            throw new \Exception($e->getMessage());
        }
    }


    /**
     * getUser
     * Recupera info do user logado
     *
     * @param null $accessToken
     * @return false|object
     */
    private static function getUser($accessToken=null) {
        try {
            if(empty($accessToken))
                throw new \Exception('Require Access Token: empty.');

            $getUserInfoUrl = sprintf(self::URL_USER_INFO,
                self::getHttpProcol(),
                ENV('PASSPORT_HOST'));

            try {
                $response = Http::withHeaders([
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer '. $accessToken,
                ])->get($getUserInfoUrl)->object();

                if(!isset($response->id) OR !isset($response->email))
                    throw new \RequestException('User data not found.');

                return $response;
            } catch (RequestException $e) {
                throw new \RequestException($e->getMessage());
            }
        } catch(\Exception $e) {
            throw new \Exception($e->getMessage());
        }
    }

    /**
     * getHttpProcol
     * Retorna Http ou Https
     *
     * @return String
     */
    protected static function getHttpProcol():String {
        return ENV('APP_ENV') != 'production' ? 'http' : 'https';
    }

    /**
     * codeChallengeGenerator
     *
     * @return String
     */
    private static function codeChallengeGenerator():String {
        $codeVerifier = Str::random(128);

        $codeChallenge = strtr(rtrim(
            base64_encode(hash('sha256', $codeVerifier, true))
            , '='), '+/', '-_');

        Session::put(self::SESSION_CHALLENGE_PRIVATE, $codeVerifier);
        Session::put(self::SESSION_CHALLENGE_PUBLIC, $codeChallenge);

        return $codeChallenge;
    }

    /**
     * codeStateGenerator
     *
     * @return String
     */
    private static function codeStateGenerator():String {
        $state = sprintf('%s%s%s',
            Str::random(256),
            self::CODE_STATE_SEPARATOR,
            /**
             * É necessário passar a Session ID junto ao Code State, pois quando
             * recebemos uma redirect 302 de uma aplicação externa, se inicia uma nova sessão.
             * Esta sessão será recuperada na self::sessionRegenerate
             */
            self::getSessionIdCrypted()
        );

        Session::put(self::SESSION_CODE_STATE, $state);

        return $state;
    }

    /**
     * getCodeSate
     *
     * @return String
     */
    public static function getCodeSate():String {
        return Session::get(self::SESSION_CODE_STATE);
    }

    /**
     * getChallengePublic
     *
     * @return String
     */
    public static function getChallengePublic():String {
        return Session::get(self::SESSION_CHALLENGE_PUBLIC);
    }


    /**
     * getSessionIdCrypted
     *
     * @return String
     */
    public static function getSessionIdCrypted():String {
        return strtr(rtrim(
            base64_encode(Crypt::encryptString(Session::getId()))
            , '='), '+/', '-_');
    }

    /**
     * getSessionIdDecrypted
     *
     * @param $sessionIdCrypted
     * @return String
     * @throws \Exception
     */
    public static function getSessionIdDecrypted($sessionIdCrypted):String {
        try {
            if(empty($sessionIdCrypted))
                throw new \Exception('Code Challenge invalid or not found.');

            return Crypt::decryptString(base64_decode(strtr($sessionIdCrypted, '-_', '+/').'='));
        } catch(DecryptException $e) {
            throw new DecryptException($e->getMessage());
        }
    }


    /**
     * validateCodeState
     *
     * @param $codeStateSessionId
     * @throws \Exception
     */
    private static function validateCodeState($codeStateSessionId):void {
        try {
            if(empty($codeStateSessionId))
                throw new \Exception('Code State invalid or not found.');

            if(strpos($codeStateSessionId, self::CODE_STATE_SEPARATOR) === false)
                throw new \Exception('Code State format invalid.');

            $sessionIdCrypted = rtrim(strstr($codeStateSessionId, self::CODE_STATE_SEPARATOR, false), self::CODE_STATE_SEPARATOR);

            $sessionId = self::getSessionIdDecrypted($sessionIdCrypted);

            self::sessionRegenarate($sessionId);

            if($codeStateSessionId != Session::get(self::SESSION_CODE_STATE))
                throw new \Exception('Code State mismatch.');
        } catch(\Exception $e){
            throw new \Exception($e->getMessage());
        }
    }


    /**
     * sessionRegenarate
     * Recupera os dados da sessão perdidos devido ao redirect 302
     *
     * @param $sessionId
     * @throws \Exception
     */
    private static function sessionRegenarate($sessionId):void {
        try {
            Session::setId($sessionId);
            Session::start();

            $challengePrivate = Session::get(self::SESSION_CHALLENGE_PRIVATE);
            $codeState = Session::get(self::SESSION_CODE_STATE);

            if(empty($challengePrivate))
                throw new \Exception('Code Challenge invalid or not found.');

            if(empty($codeState))
                throw new \Exception('Code State invalid or not found.');
        } catch(\Exception $e) {
            throw new \Exception($e->getMessage());
        }
    }
}
