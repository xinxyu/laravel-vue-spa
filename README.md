# Laravel and Vue SPA

This is a guide on setting up a Single Page Application with user login, and roles using Laravel 6 and Vue 2.6. This guide is a modification of the original guide [Create a SPA with role-based authentication with Laravel and Vue.js by Benoît Ripoche](https://medium.com/@ripoche.b/create-a-spa-with-role-based-authentication-with-laravel-and-vue-js-ac4b260b882f)

## Setting up Laravel
Create a new project with Laravel and composer

`laravel new laravel-vue-spa`

### User Table

Add roles to the user table that we'll be creating by adding it in the "create_users_table" migrations file.

    $table->integer('role')->default(1);

Seed the table by updating the "DatabaseSeeder.php" file.

    <?php
    use App\User;
    use Illuminate\Database\Seeder;
    use Illuminate\Support\Facades\Hash;class DatabaseSeeder extends Seeder
    {
        public function run()
        {
            User::create([
                'name' => 'Admin',
                'email' => 'admin@test.com',
                'password' => Hash::make('admin'),
                'role' => 2
            ]);        User::create([
                'name' => 'User',
                'email' => 'user@test.com',
                'password' => Hash::make('secret'),
                'role' => 1
            ]);
        }
    }`

Update the .env file with the database credentials.

    DB_CONNECTION=mysql
    DB_HOST=127.0.0.1
    DB_PORT=8889
    DB_DATABASE=laravel-vue-spa
    DB_USERNAME=root
    DB_PASSWORD=root

Run the migration and seed the database.

`php artisan migrate --seed`

### API Authentication Setup with JWT

Install the [tymondesigns/jwt-auth](https://github.com/tymondesigns/jwt-auth) package. Use the "dev-develop" version of the package.

`composer require tymon/jwt-auth:dev-develop`

Publish the JWT configuration

`php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"`

Create a JWT secret key

`php artisan jwt:secret`

Update "config/auth.php" with the api gaurd

    'defaults' => [
        'guard' => 'api',
        'passwords' => 'users',
    ],

Use the JWT driver for gaurds

    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],    'api' => [
            'driver' => 'jwt',
            'provider' => 'users',
        ],
    ],

Make User class implement the Authenticatable interface

    <?php
    namespace App;
    use Illuminate\Notifications\Notifiable;
    use Illuminate\Contracts\Auth\MustVerifyEmail;
    use Illuminate\Foundation\Auth\User as Authenticatable;
    use Tymon\JWTAuth\Contracts\JWTSubject;
    
    class User extends Authenticatable implements JWTSubject
    {
        use Notifiable;    
        /**
        * The attributes that are mass assignable.
        *
        * @var array
        */
        protected $fillable = [
            'name', 'email', 'password',
        ];    /**
        * The attributes that should be hidden for arrays.
        *
        * @var array
        */
        protected $hidden = [
            'password', 'remember_token',
        ];
        
        public function getJWTIdentifier()
        {
            return $this->getKey();
        }
        
        public function getJWTCustomClaims()
        {
            return [];
        }
    }

Update the authentication middleware to return a JSON response

    <?php
    namespace App\Http\Middleware;use Closure;
    use Illuminate\Auth\Middleware\Authenticate as Middleware;
    class Authenticate extends Middleware
    {
        public function handle($request, Closure $next, ...$guards)
        {
            if ($this->authenticate($request, $guards) === 'authentication_error') {
                return response()->json(['error'=>'Unauthorized']);
            }        return $next($request);
        }    protected function authenticate($request, array $guards)
        {
            if (empty($guards)) {
                $guards = [null];
            }        foreach ($guards as $guard) {
                if ($this->auth->guard($guard)->check()) {
                    return $this->auth->shouldUse($guard);
                }
            }        return 'authentication_error';
        }
    }

### Authentication Endpoints

Add routes to register, log in, log out, and get user information.

    Route::prefix('auth')->group(function () {
        Route::post('register', 'AuthController@register');
        Route::post('login', 'AuthController@login');
        Route::get('refresh', 'AuthController@refresh');    Route::group(['middleware' => 'auth:api'], function(){
            Route::get('user', 'AuthController@user');
            Route::post('logout', 'AuthController@logout');
        });
    });

Create an auth controller to handle these requests.

`php artisan make:controller AuthController`

Update ‘app/Http/Controllers/AuthController.php’ with this code

    <?php
    namespace App\Http\Controllers;use App\User;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Auth;
    use Illuminate\Support\Facades\Validator;
    class AuthController extends Controller
    {    public function register(Request $request)
        {
            $v = Validator::make($request->all(), [
                'email' => 'required|email|unique:users',
                'password'  => 'required|min:3|confirmed',
            ]);        
            if ($v->fails())
            {
                return response()->json([
                    'status' => 'error',
                    'errors' => $v->errors()
                ], 422);
            }        $user = new User;
            $user->email = $request->email;
            $user->password = bcrypt($request->password);
            $user->save();        return response()->json(['status' => 'success'], 200);
        }    public function login(Request $request)
        {
            $credentials = $request->only('email', 'password');        
            if ($token = $this->guard()->attempt($credentials)) {
                return response()->json(['status' => 'success'], 200)->header('Authorization', $token);
            }        return response()->json(['error' => 'login_error'], 401);
        }    public function logout()
        {
            $this->guard()->logout();
            return response()->json([
                'status' => 'success',
                'msg' => 'Logged out Successfully.'
            ], 200);
        }    public function user(Request $request)
        {
            $user = User::find(Auth::user()->id);        
            return response()->json([
                'status' => 'success',
                'data' => $user
            ]);
        }    public function refresh()
        {
            if ($token = $this->guard()->refresh()) {
                return response()
                    ->json(['status' => 'successs'], 200)
                    ->header('Authorization', $token);
            }        return response()->json(['error' => 'refresh_token_error'], 401);
        }    private function guard()
        {
            return Auth::guard();
        }
    }

### Endpoint Protection by Role

Create the following middleware

`php artisan make:middleware CheckIsAdmin`

Update the "CheckIsAdmin.php" file with code for verifying if the user is an admin.

    <?php
    namespace App\Http\Middleware;
    use Closure;
    use Illuminate\Support\Facades\Auth;
    class CheckIsAdmin
    {
        public function handle($request, Closure $next)
        {
            if(Auth::user()->role === 2) {
                return $next($request);
            }        else {
                return response()->json(['error' => 'Unauthorized'], 403);
            }
        }
    }


`php artisan make:middleware CheckIsAdminOrSelf`

Update the "CheckIsAdminOrSelf.php" file with code for verifying if the id on the route is the same as the current user.

    <?php
    namespace App\Http\Middleware;
    use Closure;
    use Illuminate\Support\Facades\Auth;
    class CheckIsAdminOrSelf
    {
        public function handle($request, Closure $next)
        {
            $requestedUserId = $request->route()->parameter('id');
            if(
                Auth::user()->role === 2 ||
                Auth::user()->id == $requestedUserId
            ) {
                return $next($request);
            }        else {
                return response()->json(['error' => 'Unauthorized'], 403);
            }
        }
    }

Update "Kernel.php" by adding to middleware to the $routeMiddleware array

    'isAdmin' => \App\Http\Middleware\CheckIsAdmin::class,
    'isAdminOrSelf' => \App\Http\Middleware\CheckIsAdminOrSelf::class

Create routes for getting the users data with middleware protecting them

    Route::group(['middleware' => 'auth:api'], function(){
        // Users
        Route::get('users', 'UserController@index')->middleware('isAdmin'); // only admin can see all users
        Route::get('users/{id}', 'UserController@show')->middleware('isAdminOrSelf'); // an admin can see any user, and a user can see themselves
    });

Add a CORS middleware so our API can work with external requests.

`php artisan make:middleware Cors`

Update the "Cors.php" file

    <?php

    namespace App\Http\Middleware;

    use Closure;

    class Cors
    {
        /**
        * Handle an incoming request.
        *
        * @param  \Illuminate\Http\Request  $request
        * @param  \Closure  $next
        * @return mixed
        */
        public function handle($request, Closure $next)
        {
            return $next($request)
            ->header('Access-Control-Allow-Origin', '*')
            ->header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
            ->header('Access-Control-Allow-Headers', 'Content-Type,Authorization,Content-Length,X-Requested-With')
            ->header('Access-Control-Expose-Headers', 'Authorization');
        }
    }

Update the "Kernel.php" file and add to the $middleware array

    protected $middleware = [
        \App\Http\Middleware\TrustProxies::class,
        \App\Http\Middleware\CheckForMaintenanceMode::class,
        \Illuminate\Foundation\Http\Middleware\ValidatePostSize::class,
        \App\Http\Middleware\TrimStrings::class,
        \Illuminate\Foundation\Http\Middleware\ConvertEmptyStringsToNull::class,
        \App\Http\Middleware\Cors::class // Add CORS here
    ];

Create the user controller

`php artisan make:controller UserController`

Update the user controller "UserController.php"

    <?php
    namespace App\Http\Controllers;use App\User;
    use Illuminate\Http\Request;
    class UserController extends Controller
    {
        // gets all users
        public function index()
        {
            $users = User::all();
            return response()->json(
                [
                    'status' => 'success',
                    'users' => $users->toArray()
                ], 200);
        }

        // gets a specific user
        public function show(Request $request, $id)
        {
            $user = User::find($id);
            return response()->json(
                [
                    'status' => 'success',
                    'user' => $user->toArray()
                ], 200);
        }
    }

## Setting up Vue

### Front-End Setup

Install front-end dependencies

`npm install`

Replace "welcome.blade.php" view with this code

    <!DOCTYPE html>
    <html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">  <!-- CSRF Token -->
    <meta name="csrf-token" content="{{ csrf_token() }}">  <title>{{ config('app.name', 'Laravel') }}</title>  <!-- Scripts -->
    <script src="{{ asset('js/app.js') }}" defer></script>  <!-- Fonts -->
    <link rel="dns-prefetch" href="https://fonts.gstatic.com">
    <link href="https://fonts.googleapis.com/css?family=Raleway:300,400,600" rel="stylesheet" type="text/css">  <!-- Styles -->
    <link href="{{ asset('css/app.css') }}" rel="stylesheet">
    </head>
    <body>
    <div id="app">
    <index></index>
    </div>
    </body>
    </html>

> Note : Make sure to add the ‘js/app.js’ script, the ‘<div id=”app”>’ tag and the ‘<index>’ tag.

Create an index file in "resources/js/Index.vue"

    <template>
        <div id="main">
            <header id="header">
                <h1>
                    <router-link :to="{name: 'home'}">
                        Laravel Vue SPA
                    </router-link>
                </h1>
                <navigationMenu></navigationMenu>
            </header>
            <div id="content">
                <router-view></router-view>
            </div>
        </div>
    </template><script>
    import navigationMenu from './components/Menu.vue'
    export default {
        data() {
        return {
            //
        }
        },
        components: {
        navigationMenu
        }
    }
    </script>

Update "resources/js/app.js" with this code

    import 'es6-promise/auto'
    import axios from 'axios'
    import './bootstrap'
    import Vue from 'vue'
    import VueAuth from '@websanova/vue-auth'
    import VueAxios from 'vue-axios'
    import VueRouter from 'vue-router'
    import Index from './Index'
    import auth from './auth'
    import router from './router'
    import 'bootstrap'
    import 'bootstrap/dist/css/bootstrap.min.css'

    // Set Vue globally
    window.Vue = Vue

    // Set Vue router
    Vue.router = router
    Vue.use(VueRouter)

    // Set Vue authentication
    Vue.use(VueAxios, axios)
    axios.defaults.baseURL = `${process.env.MIX_APP_URL}/api`
    Vue.use(VueAuth, auth)

    // Load Index
    Vue.component('index', Index)
    const app = new Vue({
        el: '#app',
        router
    });

The `process.env.MIX_APP_URL` is determined by the `MIX_APP_URL="${APP_URL}"` in the .env file.
You can set the APP_URL by adding an entry `APP_URL=http://127.0.0.1:8000`. Make sure to restart the Laravel server to see the changes.

### Front-End Authentication

Add packages for JWT authentication 

`npm i @websanova/vue-auth vue-router vue-axios axios es6-promise`

Create an "resources/js/auth.js" file with this code. This file will configure endpoints for login and logout.

    import bearer from '@websanova/vue-auth/drivers/auth/bearer'
    import axios from '@websanova/vue-auth/drivers/http/axios.1.x'
    import router from '@websanova/vue-auth/drivers/router/vue-router.2.x'
    // Auth base configuration some of this options
    // can be override in method calls
    const config = {
        auth: bearer,
        http: axios,
        router: router,
        tokenDefaultName: 'laravel-vue-spa',
        tokenStore: ['localStorage'],
        rolesVar: 'role',
        registerData: { url: 'auth/register', method: 'POST', redirect: '/login' },
        loginData: { url: 'auth/login', method: 'POST', redirect: '', fetchUser: true },
        logoutData: { url: 'auth/logout', method: 'POST', redirect: '/', makeRequest: true },
        fetchData: { url: 'auth/user', method: 'GET', enabled: true },
        refreshData: { url: 'auth/refresh', method: 'GET', enabled: true, interval: 30 }
    }
    export default config

Add "resources/js/router.js" file

    import VueRouter from 'vue-router'// Pages
    import Home from './pages/Home'
    import Register from './pages/Register'
    import Login from './pages/Login'
    import Dashboard from './pages/user/Dashboard'
    import AdminDashboard from './pages/admin/Dashboard'// Routes
    const routes = [
        {
            path: '/',
            name: 'home',
            component: Home,
            meta: {
                auth: false
            }
        },
        {
            path: '/register',
            name: 'register',
            component: Register,
            meta: {
                auth: false
            }
        },
        {
            path: '/login',
            name: 'login',
            component: Login,
            meta: {
                auth: false
            }
        },
        // USER ROUTES
        {
            path: '/dashboard',
            name: 'dashboard',
            component: Dashboard,
            meta: {
                auth: true
            }
        },
        // ADMIN ROUTES
        {
            path: '/admin',
            name: 'admin.dashboard',
            component: AdminDashboard,
            meta: {
                auth: { roles: 2, redirect: { name: 'login' }, forbiddenRedirect: '/403' }
            }
        },
    ]
    const router = new VueRouter({
        history: true,
        mode: 'history',
        routes,
    })

    export default router

Add the "resources/js/Home.vue" file

    <template>
    <div class="container">
        <div class="card card-default">
        <div class="card-header">Hello</div>
        <div class="card-body">
            <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
        </div>
        </div>
    </div>
    </template>

Add the "resources/js/Register.vue" file

    <template>
    <div class="container">
        <div class="card card-default">
        <div class="card-header">Register</div>
        <div class="card-body">
            <div class="alert alert-danger" v-if="has_error && !success">
            <p
                v-if="error == 'registration_validation_error'">
                Error validating form.</p>
            <p
                v-else
            >Error.</p>
            </div>
            <form autocomplete="off" @submit.prevent="register" v-if="!success" method="post">
            <div class="form-group" v-bind:class="{ 'has-error': has_error && errors.email }">
                <label for="email">E-mail</label>
                <input
                type="email"
                id="email"
                class="form-control"
                placeholder="user@example.com"
                v-model="email"
                />
                <span class="help-block" v-if="has_error && errors.email">{{ errors.email }}</span>
            </div>
            <div class="form-group" v-bind:class="{ 'has-error': has_error && errors.password }">
                <label for="password">Password</label>
                <input type="password" id="password" class="form-control" v-model="password" />
                <span class="help-block" v-if="has_error && errors.password">{{ errors.password }}</span>
            </div>
            <div class="form-group" v-bind:class="{ 'has-error': has_error && errors.password }">
                <label for="password_confirmation">Confirm Password</label>
                <input
                type="password"
                id="password_confirmation"
                class="form-control"
                v-model="password_confirmation"
                />
            </div>
            <button type="submit" class="btn btn-default">Register</button>
            </form>
        </div>
        </div>
    </div>
    </template>
    <script>
    export default {
    data() {
        return {
        name: "",
        email: "",
        password: "",
        password_confirmation: "",
        has_error: false,
        error: "",
        errors: {},
        success: false
        };
    },
    methods: {
        register() {
        var app = this;
        this.$auth.register({
            data: {
            email: app.email,
            password: app.password,
            password_confirmation: app.password_confirmation
            },
            success: function() {
            app.success = true;
            this.$router.push({
                name: "login",
                params: { successRegistrationRedirect: true }
            });
            },
            error: function(res) {
            console.log(res.response.data.errors);
            app.has_error = true;
            app.error = res.response.data.error;
            app.errors = res.response.data.errors || {};
            }
        });
        }
    }
    };
    </script>

Add the "resources/js/Login.vue" file

    <template>
        <div class="container">
            <div class="card card-default">
                <div class="card-header">Log In</div>            <div class="card-body">
                    <div class="alert alert-danger" v-if="has_error">
                        <p>Error, incorrect credentials.</p>
                    </div>
                    <form autocomplete="off" @submit.prevent="login()" method="post">
                        <div class="form-group">
                            <label for="email">E-mail</label>
                            <input type="email" id="email" class="form-control" placeholder="user@example.com" v-model="email" required>
                        </div>
                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" class="form-control" v-model="password" required>
                        </div>
                        <button type="submit" class="btn btn-default" >Log In</button>
                    </form>
                </div>
            </div>
        </div>
    </template><script>
    export default {
        data() {
        return {
            email: 'admin@test.com',
            password: 'admin',
            has_error: false
        }
        },    mounted() {
        //
        },    methods: {
        login() {
            // get the redirect object
            var redirect = this.$auth.redirect()
            var app = this
            this.$auth.login({
            data: {
                email: app.email,
                password: app.password
            },
            success: function(f) {
                // handle redirection
                console.log('success', f);
                const redirectTo = redirect ? redirect.from.name : this.$auth.user().role === 2 ? 'admin.dashboard' : 'dashboard'
                this.$router.push({name: redirectTo})
            },
            error: function() {
                app.has_error = true
            },
            rememberMe: true,
            fetchUser: true
            })
        }
        }
    }
    </script>

Add the "resources/js/Register.vue" file

    <template>
    <div class="container">
        <div class="card card-default">
        <div class="card-header">Register</div>
        <div class="card-body">
            <div class="alert alert-danger" v-if="has_error && !success">
            <p
                v-if="error == 'registration_validation_error'">
                Error validating form.</p>
            <p
                v-else
            >Error.</p>
            </div>
            <form autocomplete="off" @submit.prevent="register" v-if="!success" method="post">
            <div class="form-group" v-bind:class="{ 'has-error': has_error && errors.email }">
                <label for="email">E-mail</label>
                <input
                type="email"
                id="email"
                class="form-control"
                placeholder="user@example.com"
                v-model="email"
                />
                <span class="help-block" v-if="has_error && errors.email">{{ errors.email }}</span>
            </div>
            <div class="form-group" v-bind:class="{ 'has-error': has_error && errors.password }">
                <label for="password">Password</label>
                <input type="password" id="password" class="form-control" v-model="password" />
                <span class="help-block" v-if="has_error && errors.password">{{ errors.password }}</span>
            </div>
            <div class="form-group" v-bind:class="{ 'has-error': has_error && errors.password }">
                <label for="password_confirmation">Confirm Password</label>
                <input
                type="password"
                id="password_confirmation"
                class="form-control"
                v-model="password_confirmation"
                />
            </div>
            <button type="submit" class="btn btn-default">Register</button>
            </form>
        </div>
        </div>
    </div>
    </template>
    <script>
    export default {
    data() {
        return {
        name: "",
        email: "",
        password: "",
        password_confirmation: "",
        has_error: false,
        error: "",
        errors: {},
        success: false
        };
    },
    methods: {
        register() {
        var app = this;
        this.$auth.register({
            data: {
            email: app.email,
            password: app.password,
            password_confirmation: app.password_confirmation
            },
            success: function() {
            app.success = true;
            this.$router.push({
                name: "login",
                params: { successRegistrationRedirect: true }
            });
            },
            error: function(res) {
            console.log(res.response.data.errors);
            app.has_error = true;
            app.error = res.response.data.error;
            app.errors = res.response.data.errors || {};
            }
        });
        }
    }
    };
    </script>

Add the "resources/js/pages/user/Dashboard.vue" file

    <template>
    <div class="container">
        <div class="card card-default">
        <div class="card-header">Dashboard</div>
        <div class="card-body">Hello</div>
        </div>
    </div>
    </template><script>
    export default {
    data() {
        return {
        //
        };
    },
    components: {
        //
    }
    };
    </script>

Add the "resources/js/pages/admin/Dashboard.vue" file

    <template>
    <div class="container">
        <div class="card card-default">
        <div class="card-header">Admin Dashboard</div>
        <div class="card-body">Hello, welcome to the Admin Dashboard</div>
        </div>
        <div class="card card-default">
        <div class="card-header">List of All Users</div>
        <div class="card-body">
            <userList></userList>
        </div>
        </div>
    </div>
    </template><script>
    import userList from "../../components/user-list.vue";
    export default {
    mounted() {
        //
    },
    components: {
        userList
    }
    };
    </script>

Add the "resources/components/Menu.vue" file

    <template>
        <nav id="nav">
            <ul>
                <!--UNLOGGED-->
                <li v-if="!$auth.check()" v-for="(route, key) in routes.unlogged" v-bind:key="route.path">
                    <router-link  :to="{ name : route.path }" :key="key">
                        {{route.name}}
                    </router-link>
                </li>
                <!--LOGGED USER-->
                <li v-if="$auth.check(1)" v-for="(route, key) in routes.user" v-bind:key="route.path">
                    <router-link  :to="{ name : route.path }" :key="key">
                        {{route.name}}
                    </router-link>
                </li>
                <!--LOGGED ADMIN-->
                <li v-if="$auth.check(2)" v-for="(route, key) in routes.admin" v-bind:key="route.path">
                    <router-link  :to="{ name : route.path }" :key="key">
                        {{route.name}}
                    </router-link>
                </li>
                <!--LOGOUT-->
                <li v-if="$auth.check()">
                    <a href="#" @click.prevent="$auth.logout()">Logout</a>
                </li>
            </ul>
        </nav>
    </template><script>
    export default {
        data() {
        return {
            routes: {
            // UNLOGGED
            unlogged: [
                {
                name: 'Register',
                path: 'register'
                },
                {
                name: 'Login',
                path: 'login'
                }
            ],          // LOGGED USER
            user: [
                {
                name: 'Dashboard',
                path: 'dashboard'
                }
            ],
            // LOGGED ADMIN
            admin: [
                {
                name: 'Dashboard',
                path: 'admin.dashboard'
                }
            ]
            }
        }
        },
        mounted() {
        //
        }
    }
    </script>

Add the "resources/components/user-list.vue" file

    <template>
    <div>
        <h3>List of Users</h3>
        <div class="alert alert-danger" v-if="has_error">
            <p>Error</p>
        </div>    <table class="table">
            <tr>
                <th scope="col">Id</th>
                <th scope="col">Name</th>
                <th scope="col">Email</th>
                <th scope="col">Date Registered</th>
            </tr>
            <tr v-for="user in users" v-bind:key="user.id" style="margin-bottom: 5px;">
                <th scope="row">{{ user.id }}</th>
                <td>{{ user.name }}</td>
                <td>{{ user.email }}</td>
                <td>{{ user.created_at}}</td>        </tr>
        </table></div>
    </template><script>
    export default {
        data() {
        return {
            has_error: false,
            users: null
        }
        },    mounted() {
        this.getUsers()
        },    methods: {
        getUsers() {
            this.$http({
            url: `users`,
            method: 'GET'
            })
                .then((res) => {
                this.users = res.data.users
                }, () => {
                this.has_error = true
                })
        }
        }
    }
    </script>


## Moving to Production Server

1. create a database in MySQL
2. create the .env file
3. update the .env file with APP_URL, MIX_APP_URL, database name, database password 
4. composer install
5. `php artisan jwt:secret`
