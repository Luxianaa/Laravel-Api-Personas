<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Firebase\JWT\JWT;
use App\Models\User;
use Firebase\JWT\Key;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        //1. Buscar usuario por email en la base de datos
        //      (se asume que el modelo User ya está importado)
        $usuario = User::where('email', $request->email)->first();

        //2. Si no existe el usuario → devolver error
        if ($usuario == null) {
            return response()->json([
                'mensaje' => 'Usuario inválido',
            ], 400);
        }

        //3. Verificar que la contraseña ingresada coincida con la guardada (encriptada)
        if (Hash::check($request->password, $usuario->password)) {

            //4. Obtener la clave y algoritmo definidos en el archivo .env
            $key = env('JWT_SECRET');
            $algoritmo = env('JWT_ALGORITHM');

            //5. Crear el token JWT con información básica del usuario
            $time = time(); // tiempo actual
            $token = array(
                'iat' => $time,              // Fecha de emisión (issued at)
                'exp' => $time + (1200 * 60), // Fecha de expiración (+1 hora aprox.)
                'data' => [                  // Datos que viajarán dentro del token
                    'user_id' => $usuario->id,
                ],
            );

            //6. Codificar el token con la clave secreta y el algoritmo HS256
            $jwt = JWT::encode($token, $key, $algoritmo);

            // 7. Devolver respuesta exitosa con el token generado
            return response()->json([
                'mensaje' => 'Se logró autenticar al usuario',
                'token' => $jwt,               // Token JWT
                'type' => 'bearer',            // Tipo de token (para el header Authorization)
                'expires' => $time + (1200 * 60), // Fecha de expiración
                'usuario' => $usuario          // Datos del usuario autenticado
            ], 200);
        } 
        else {
            //8. Si la contraseña no coincide → error de autenticación
            return response()->json([
                'mensaje' => 'Contraseña inválida',
                'status' => 400
            ], 400);
        }
    }
}
