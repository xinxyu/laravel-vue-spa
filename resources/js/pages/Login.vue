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