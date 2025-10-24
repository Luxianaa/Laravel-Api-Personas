<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Firebase\JWT\JWT;//librería para manejar JWT
use Firebase\JWT\Key;//librería para manejar claves JWT

class JwtMiddleware
{
    /**
     * Verifica el token JWT antes de permitir acceso a las rutas protegidas
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            //1. Obtener el header Authorization (formato: "Bearer <token>")
            $autorizacion = $request->header('Authorization');

            //2. Extraer solo el token (quita los primeros 7 caracteres "Bearer ")
            $jwt = substr($autorizacion, 7);

            //3. Leer clave secreta y algoritmo desde el archivo .env
            $key = env('JWT_SECRET');
            $algoritmo = env('JWT_ALGORITHM');

            //4. Decodificar el token usando la librería Firebase JWT
            //Verifica firma, expiración y obtiene los datos (payload)
            $datos = JWT::decode($jwt, new Key($key, $algoritmo));

            //5. Agregar los datos del usuario al request
            //(para usarlos luego en los controladores)
            $request->attributes->add(['usuario' => $datos->data]);
        }
        catch (\Exception $e) {
            //6. Si hay error (token inválido, expirado, ausente)
            //se devuelve una respuesta 401 "No autorizado"
            return response()->json(['status' => 'No autorizado ' . $e->getMessage()], 401);
        }

        //7. Si todo está bien, continúa la petición al siguiente middleware/controlador
        return $next($request);
    }
}
