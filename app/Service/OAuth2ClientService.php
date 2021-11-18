<?php

namespace App\Services;

use App\Http\Requests\Request;
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
    const PASSPORT_SESSION_STATE = '_passport_state';
    const PASSPORT_SESSION_CODE_VERIFIER = '_passport_code_verifier';

    /**
     * redirectToLoginProvider
     * Retorna a URL de login do Autorizador
     *
     * @return String
     */
    public static function redirectToLoginProvider():String {
        return sprintf(self::URL_AUTHORIZE,
            static::getHttpProcol(),
            ENV('PASSPORT_HOST'),
            http_build_query([
                'client_id' => ENV('PASSPORT_CLIENT_ID'),
                'redirect_url' => ENV('PASSPORT_REDIRECT_URL'),
                'response_type' => 'code',
                'state' => self::codeState(),
                'code_challenge' => self::codeChallenge(),
                'code_challenge_method' => 'S256',
            ])
        );
    }

    /**
     * redirectToLogoutProvider
     * Retorna a URL de logout do Autorizador
     *
     * @return String
     */
    public static function redirectToLogoutProvider():String {
        return sprintf(self::URL_LOGOUT,
            static::getHttpProcol(),
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
            $codeVerifierSession = Session::get(self::PASSPORT_SESSION_CODE_VERIFIER);
            $stateSession = Session::get(self::PASSPORT_SESSION_STATE);
            $code  = \request()->input('code');
            $state = \request()->input('state');

            if(empty($codeVerifierSession))
                throw new \Exception('Código de verificação não encontrado.');

            if(empty($code))
                throw new \Exception('Código de autorização não informado.');

            if(empty($state) OR empty($stateSession) OR $state != $stateSession)
                throw new \Exception('Não foi possível validar o estado.');

            $tokenUrl = sprintf(self::URL_TOKEN,
                static::getHttpProcol(),
                ENV('PASSPORT_HOST'));

            try {
                $response = Http::post($tokenUrl, [
                    'grant_type' => 'authorization_code',
                    'client_id' => ENV('PASSPORT_CLIENT_ID'),
                    'client_secret' => ENV('PASSPORT_CLIENT_SECRET'),
                    'redirect_url' => ENV('PASSPORT_REDIRECT_URI'),
                    'code_verifier' => $codeVerifierSession,
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
                static::getHttpProcol(),
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
    protected static function codeChallenge():String {
        $codeVerifier = Str::random(128);

        $codeChallenge = strtr(rtrim(
            base64_encode(hash('sha256', $codeVerifier, true))
            , '='), '+/', '-_');

        Session::put(self::PASSPORT_SESSION_STATE, $codeVerifier);

        return $codeChallenge;
    }

    /**
     * codeState
     * @return String
     */
    protected static function codeState():String {
        $state = Str::random(256);

        Session::put(self::PASSPORT_SESSION_STATE, $state);

        return $state;
    }
}
