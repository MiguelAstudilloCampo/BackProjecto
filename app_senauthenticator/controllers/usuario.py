from app_senauthenticator.models import Usuario,PasswordReset # Se importa el modelo
from app_senauthenticator.serializers.usuario import UsuarioSerializer # Se importa el serializador
from rest_framework.decorators import api_view, authentication_classes, permission_classes # Decoradores que manejan peticiones HTTP, autenticaciones y permisos
from rest_framework.response import Response # Decorador para devolver respuestas HTTP
from rest_framework import status # Decorador para usar códigos de estado HTTP
from rest_framework.authtoken.models import Token # Se importa el modelo Token de DRF
from rest_framework.authentication import TokenAuthentication # Decorador para generar un Token de autenticación
from rest_framework. permissions import IsAuthenticated # Decorador para confirmar una autenticación
from datetime import timedelta
# ////////nuevas importaciones /////////
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
# from django.contrib.auth import authenticate, login, logout
# from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone
from django.urls import reverse



@api_view(['GET', 'POST', 'PUT', 'DELETE']) # Se especifica las solicitudes HTTP que va a manejar el controlador
def usuario_controlador(request, pk=None): # La función contiene dos parámetros, request: Recibe las solicitudes HTTP y pk: Recibe la primary key de un dato.
    # Si existe la pk se manejan los métodos GET, PUT, DELETE
    if pk:
        try:
            usuario = Usuario.objects.get(pk=pk) # Se intenta obtener el objeto por su pk
        except Usuario.DoesNotExist:
            return Response({'error': 'Usuario no encontrado.'}, status=status.HTTP_404_NOT_FOUND) # Si el objeto no existe se devuelve un código de estado 404, indicando que no fue encontrada la solicitud
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR) # Si ocurre cualquier otro error, se devuelve un código de estado 500, indicando un error interno en el servidor

        # Solicitud para obtener un objeto
        if request.method == 'GET':
            try:
                serializer = UsuarioSerializer(usuario) # Se intenta serializar el objeto
                return Response(serializer.data) # Se devuelve el objeto serializado
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Solicitud para actualizar un objeto
        if request.method == 'PUT':
            try:
                serializer = UsuarioSerializer(usuario, data=request.data) # Se intenta serializar el objeto, y los nuevos datos actualizados
                if serializer.is_valid(): # si los datos son válidos
                    serializer.save() # Se guarda el objeto actualizado
                    return Response(serializer.data, status=status.HTTP_200_OK) # Se devuelve una respuesta con el objeto actualizado, y un código de estado 200, confirmando que la solicitud es correcta.
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) # Si los datos no son válidos, se devuelve un código de estado 400, indicando una solicitud incorrecta.
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Solicitud para eliminar un objeto
        if request.method == 'DELETE':
            try:
                usuario.delete() # Se intenta eliminar el objeto
                return Response(status=status.HTTP_204_NO_CONTENT) # Si se elimina, se devuelve una respuesta con un código de estado 204, indicando que la solicitud es correcta pero no hay contenido para mostrar
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Si no existe la pk se manejan los métodos GET, POST
    else:
        # Solicitud para obtener todos los objetos en una lista
        if request.method == 'GET':
            try:
                usuarios = Usuario.objects.all() # Se intenta obtener todos los objetos
                serializer = UsuarioSerializer(usuarios, many=True) # Se serializan los objetos, la opción many=True indica que se están serializando múltiples objetos
                return Response(serializer.data) # Se devuelve una respuesta con los objetos serializados
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)                

        # Solicitud para crear un objeto
        elif request.method == 'POST':
            try:
                serializer = UsuarioSerializer(data=request.data) # Se intenta serializar el objeto recibido 

                if serializer.is_valid(): # si el objeto es válido
                    serializer.save() # Se guarda 

                    user = Usuario.objects.get(numero_documento_usuario=serializer.data['numero_documento_usuario']) # Se obtiene el objeto mediante el número de documento
                    user.set_password(serializer.data['password']) # La función set_password() encripta la contraseña para guardarla de forma segura en la base de datos
                    user.save() # Se guarda el usuario con la contraseña encriptada

                    token = Token.objects.create(user=user) # Se crea el token de autenticación para el usuario creado

                    return Response({'token': token.key, 'usuario': serializer.data}, status=status.HTTP_201_CREATED) # Se devuelve una respuesta con el token, el usuario y un código de estado 201, indicando que el objeto fue creado
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) # Si el objeto no es válido, se devuelve un código de estado 400, indicando una solicitud incorrecta
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            

# @api_view(['POST']) # Se utiliza el método POST para enviar las credenciales del usuario al servidor 
# def inicio_sesion(request):
#     try:        
#         user = Usuario.objects.get(numero_documento_usuario=request.data['numero_documento_usuario']) # Se obtiene el usuario mediante el número de documento
        
#         # Si la contraseña es inválida
#         if not user.check_password(request.data['password']): # La función check_password() compara un string con un dato encriptado, en este caso la contraseña recien ingresada, con la contraseña encriptada guardada en la base de datos
#             return Response({'error': 'Contraseña inválida.'}, status=status.HTTP_400_BAD_REQUEST)
        
#         # Si la contraseña es válida
#         token, created = Token.objects.get_or_create(user=user) # Se obtiene un token existente, si no existe se crea
#         serializer = UsuarioSerializer(instance=user) # Se serializa los datos del usuario
#         return Response({'token': token.key, 'user': serializer.data}, status=status.HTTP_200_OK)

#     except Usuario.DoesNotExist: # Si el usuario no existe
#         return Response({'error': 'Debe registrarse.'}, status=status.HTTP_404_NOT_FOUND)
#     except Exception as e:
#         return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)        

@api_view(['POST'])
def inicio_sesion(request):
    try:        
        user = Usuario.objects.get(numero_documento_usuario=request.data['numero_documento_usuario']) # Se obtiene el usuario mediante el número de documento
        
        # Si la contraseña es inválida
        if not user.check_password(request.data['password']):
            return Response({'error': 'Contraseña inválida.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Si la contraseña es válida
        token, created = Token.objects.get_or_create(user=user)
        serializer = UsuarioSerializer(instance=user)

        response = Response({'user': serializer.data}, status=status.HTTP_200_OK)

        # Añadir el token a las cookies
        response.set_cookie(
            key='auth_token',
            value=token.key,
            httponly=False,
            secure=True,  # Cambia a False si estás en desarrollo y usas HTTP
            samesite='none',  # Cambia a 'None' si el frontend y backend están en dominios diferentes
            max_age=3600,  # Expira en 1 hora (3600 segundos)
)

        return response

    except Usuario.DoesNotExist:
        return Response({'error': 'Debe registrarse.'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET']) # Se utiliza el método GET para recibir las credenciales del usuario 
@authentication_classes([TokenAuthentication]) # Se utiliza autenticación por token
@permission_classes([IsAuthenticated]) # Se requiere que el usuario esté autenticado
def perfil(request):
    try:
        serializer = UsuarioSerializer(instance=request.user) # Se serializa los datos del usuario

        # return Response(f'El usuario {serializer.data["first_name"]} {serializer.data["last_name"]} está activo en el sistema.')
        return Response({'user': serializer.data}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
# ///////////
def ForgotPassword(request):

    if request.method == "POST":
        email = request.POST.get('email')

        try:
            user = Usuario.objects.get(email=email)

            new_password_reset = PasswordReset(user=user)
            new_password_reset.save()

            password_reset_url = reverse('reset-password', kwargs={'reset_id': new_password_reset.reset_id})

            full_password_reset_url = f'{request.scheme}://{request.get_host()}{password_reset_url}'

            email_body = f'Reseta tu contraseña con este link:\n\n\n{full_password_reset_url}'
        
            email_message = EmailMessage(
                'Resete tu contraseña', # email subject
                email_body,
                settings.EMAIL_HOST_USER, # email sender
                [email] # email  receiver 
            )

            email_message.fail_silently = True
            email_message.send()

            return redirect('password-reset-sent', reset_id=new_password_reset.reset_id)

        except User.DoesNotExist:
            messages.error(request, f"Ningun usuario con este correo '{email}' encontrado")
            return redirect('forgot-password')

    return render(request, 'forgot_password.html')

def PasswordResetSent(request, reset_id):

    if PasswordReset.objects.filter(reset_id=reset_id).exists():
        return render(request, 'password_reset_sent.html')
    else:
        # redirect to forgot password page if code does not exist
        messages.error(request, 'Invalid reset id')
        return redirect('forgot-password')

def ResetPassword(request, reset_id):

    try:
        password_reset_id = PasswordReset.objects.get(reset_id=reset_id)

        if request.method == "POST":
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            passwords_have_error = False

            if password != confirm_password:
                passwords_have_error = True
                messages.error(request, 'Contraseñas no coinciden')

            if len(password) < 8:
                passwords_have_error = True
                messages.error(request, 'La contraseña debe ser mator a 8 digitos')

            expiration_time = password_reset_id.created_when + timezone.timedelta(minutes=10)

            if timezone.now() > expiration_time:
                passwords_have_error = True
                messages.error(request, 'El link ha expirado')

                password_reset_id.delete()

            if not passwords_have_error:
                user = password_reset_id.user
                user.set_password(password)
                user.save()

                password_reset_id.delete()

                messages.success(request, 'Contraseña reseteada. Procede a loguearte')
                return redirect('login')
            else:
                # redirect back to password reset page and display errors
                return redirect('reset-password', reset_id=reset_id)

    
    except PasswordReset.DoesNotExist:
        
        # redirect to forgot password page if code does not exist
        messages.error(request, 'Invalido reseteo id')
        return redirect('forgot-password')

    return render(request, 'reset_password.html')