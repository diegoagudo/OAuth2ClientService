<?php

namespace App\Services;

use App\Http\Requests\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Session;

/**
 * Class OAuth2ClientService
 * @package App\Services
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
     * Retorna a URL de logout do Autorizador
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
     * Validação do código de autorização e solicitação de token de acesso
     *
     * @return mixed
     */
    public static function handleLoginProviderCallback() {
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
                    throw new \Exception($result->error_description??'Erro desconhecido.');

                if(!isset($response->access_token) OR !isset($response->refresh_token))
                    throw new \Exception('Token de acesso não encontrada.');

                $getUser = self::getUser($response->access_token);

                if(!$getUser)
                    throw new \Exception('Usuário não encontrado.');

                $response->getUser = $getUser;

                return $response;
            } catch (\Exception $e) {
                throw new \Exception($e->getMessage());
            }

            return false;
        } catch(\Exception $e) {
            throw new \Exception($e->getMessage());
        }
    }

    /**
     * getUser
     * Recupera informações do usuário no autorizador
     *
     * @param null $accessToken
     * @return mixed
     */
    private static function getUser($accessToken=null) {
        try {
            if(empty($accessToken))
                throw new \Exception('Token de acesso não informado.');

            $getUserInfoUrl = sprintf(self::URL_USER_INFO,
                self::getHttpProcol(),
                ENV('PASSPORT_HOST'));

            try {
                $response = Http::withHeaders([
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer '. $accessToken,
                ])->get($getUserInfoUrl)->object();

                if(!isset($response->id) OR !isset($response->email))
                    throw new \Exception('Usuário não encontrado.');

                return $response;
            } catch (\Exception $e) {
                throw new \Exception($e->getMessage());
            }

            return false;
        } catch(\Exception $e) {
            return false;
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
     * codeChallenge
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
     * codeState
     * @return String
     */
    private static function codeStateGenerator():String {
        $state = sprintf('%s.%s',
            Str::random(256),
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
     * getCurrentCodeSate
     *
     * @return String
     */
    public static function getCodeSate():String {
        return Session::get(self::SESSION_CODE_STATE);
    }

    /**
     * getCurrentChallengePublic
     *
     * @return String
     */
    public static function getChallengePublic():String {
        return Session::get(self::SESSION_CHALLENGE_PUBLIC);
    }

    /**
     * getSessionIdCrypted
     * @return String
     */
    public static function getSessionIdCrypted():String {
        return strtr(rtrim(
            base64_encode(Crypt::encryptString(Session::getId()))
            , '='), '+/', '-_');
    }

    /**
     * validateCodeState
     *
     * @param $sessionId
     * @return void
     */
    private static function validateCodeState($codeStateSessionId):void {
        try {
            if(empty($codeStateSessionId))
                throw new \Exception('Code State não encontrado ou inválido.');

            if(strpos($codeStateSessionId,'.') === false)
                throw new \Exception('Formato do Code State inválido.');

            [$codeState,$sessionIdCrypted] = explode('.',$codeStateSessionId);

            $sessionId = Crypt::decryptString(base64_decode(strtr($sessionIdCrypted, '-_', '+/').'='));

            self::sessionRegenarate($sessionId);

            if($codeStateSessionId != Session::get(self::SESSION_CODE_STATE))
                throw new \Exception('Code State inválido.');
        } catch(\Exception $e){
            throw new \Exception($e->getMessage());
        }
    }

    /**
     * sessionRegenarate
     * Recuperando os dados da sessão perdidos devido ao redirect 302
     *
     * @param $sessionId
     */
    private static function sessionRegenarate($sessionId):void {
        try {
            Session::setId($sessionId);
            Session::start();

            $challengePrivate = Session::get(self::SESSION_CHALLENGE_PRIVATE);
            $codeState = Session::get(self::SESSION_CODE_STATE);

            if(empty($challengePrivate))
                throw new \Exception('Code Challenge não encontrado ou inválido.');

            if(empty($codeState))
                throw new \Exception('Code State não enocntrado ou inválido.');
        } catch(\Exception $e) {
            throw new \Exception($e->getMessage());
        }
    }
}
