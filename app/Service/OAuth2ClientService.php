<?php


namespace App\Services;

use App\Http\Requests\Request;
use Illuminate\Support\Facades\Http;
use Session;

/**
 * Class OAuth2ClientService
 * @package App\Services
 */
class OAuth2ClientService
{
    const URL_AUTHORIZE = '%s/oauth/authorize?%s';
    const URL_LOGOUT    = '%s/oauth/logout?%s';
    const URL_TOKEN     = '%s/oauth/token';
    const URL_USER_INFO = '%s/api/user';

    /**
     * redirectToLoginProvider
     * Retorna a URL de login do Autorizador
     *
     * @return String
     */
    public static function getLoginUrl():String {
        $state = \Illuminate\Support\Str::random(256);

        return sprintf(static::getHttpProcol() . self::URL_AUTHORIZE,
            ENV('PASSPORT_HOST'),
            http_build_query([
                'client_id' => ENV('PASSPORT_CLIENT_ID'),
                'redirect_url' => ENV('PASSPORT_REDIRECT_URL'),
                'response_type' => 'code',
                'state' => $state,
            ])
        );
    }

    /**
     * redirectToLogoutProvider
     * Retorna a URL de logout do Autorizador
     *
     * @return String
     */
    public static function getLogoutUrl():String {
        return sprintf(static::getHttpProcol() . self::URL_LOGOUT,
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
            $code = \request()->input('code');

            if(empty($code))
                throw new \Exception('Código de autorização não informado.');

            $tokenUrl = sprintf(static::getHttpProcol() . self::URL_TOKEN, ENV('PASSPORT_HOST'));

            try {
                $response = Http::post($tokenUrl, [
                    'grant_type' => 'authorization_code',
                    'client_id' => ENV('PASSPORT_CLIENT_ID'),
                    'client_secret' => ENV('PASSPORT_CLIENT_SECRET'),
                    'redirect_url' => ENV('PASSPORT_REDIRECT_URI'),
                    'code' => $code
                ])->object();

                if(isset($response->error))
                    throw new \Exception($result->error_description??'Erro desconhecido.');

                if(!isset($response->access_token) OR !isset($response->refresh_token))
                    throw new \Exception('Token de acesso não encontrada.');

                $getUser = self::getUserInfo($response->access_token);

                if(!$getUser)
                    throw new \Exception('Usuário não encontrado.');

                $response->getUser = $getUser;

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
     * getUser
     * Recupera informações do usuário no autorizador
     *
     * @param null $accessToken
     * @return mixed
     */
    private static function c($accessToken=null) {
        try {
            if(empty($accessToken))
                throw new \Exception('Token de acesso não informado.');

            $getUserInfoUrl = sprintf(static::getHttpProcol() . self::URL_USER_INFO, ENV('PASSPORT_HOST'));

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
        return ENV('APP_ENV') != 'production' ? 'http://' : 'https://';
    }
}
