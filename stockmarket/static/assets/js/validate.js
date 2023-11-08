const password_input = document.querySelector("#password_input");
const login_password_input = document.querySelector("#login_password_input");
const password_input2 = document.querySelector("#Confirmpassword");
const password_eye = document.querySelector("#password_eye");
const login_password_eye = document.querySelector("#login_password_eye");
const confirmPasswordeye = document.querySelector("#cpassword_eye");
let loweruppercase = document.querySelector(".loweruppercase div");

let numbercase = document.querySelector(".numbercase div");
let specialcase = document.querySelector(".specialcase div");
let numcharacter = document.querySelector(".numcharacter div");

function passStrength(pass){

    if(pass.length>7){

        numcharacter.classList.add("icon_valid");
        numcharacter.classList.remove("icon_invalid");
    }else{

        numcharacter.classList.remove("icon_valid");
        numcharacter.classList.add("icon_invalid");
    }
    if(pass.match(/([a-z].*[A-Z])|([A-Z].*[a-z])/)){
        loweruppercase.classList.add("icon_valid");
        loweruppercase.classList.remove("icon_invalid");
    }else{
        loweruppercase.classList.remove("icon_valid");
        loweruppercase.classList.add("icon_invalid");
    }
    if(pass.match(".*\\d.*")){
        numbercase.classList.add("icon_valid");
        numbercase.classList.remove("icon_invalid");
    } else {
        numbercase.classList.remove("icon_valid");
        numbercase.classList.add("icon_invalid");
    }
    if(pass.match(/[`!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/)){

        specialcase.classList.add("icon_valid");
        specialcase.classList.remove("icon_invalid");
    }else{
        specialcase.classList.remove("icon_valid");
        specialcase.classList.add("icon_invalid");
    }
}
    
var password = document.getElementById('password_input');
let random_password = document.querySelector('#random_password');
var passwordLength = 14;
var passwordVal = "";

window.onload = function loadPassword() {

    let randomGenerateChars = "B&vp3hSMQQsu#sR2+mTJx6kf6kHhHk^nNceWW_$=tEG#";

    for (var i = 0; i < passwordLength; i++) {
        let randomNumber = Math.floor(Math.random() * randomGenerateChars.length);
        passwordVal += randomGenerateChars.substring(randomNumber, randomNumber + 1);
    }

}; 


$(document).ready(function () {
    $('.alert__close').click(function (e) {
        $('.base_error_msg_container').hide();
    });
    $('.base_error_msg_container').hide();
    $(".loader").hide();
    $('#password_eye').click(function (e) {
        if (password_input.type == "password") {
            password_input.type = "text";
            password_eye.classList.add("fa-eye");
            password_eye.classList.remove("fa-eye-slash");
        } else if (password_input.type == "text") {
            password_input.type = "password";
            password_eye.classList.add("fa-eye-slash");
            password_eye.classList.remove("fa-eye");
        }
    });
    $('#login_password_eye').click(function (e) {
        if (login_password_input.type == "password") {
            login_password_input.type = "text";
            login_password_eye.classList.add("fa-eye");
            login_password_eye.classList.remove("fa-eye-slash");
        } else if (login_password_input.type == "text") {
            login_password_input.type = "password";
            login_password_eye.classList.add("fa-eye-slash");
            login_password_eye.classList.remove("fa-eye");
        }
    });
    $('#cpassword_eye').click(function (e) {
        if (password_input2.type == "password") {
            password_input2.type = "text";
            confirmPasswordeye.classList.add("fa-eye");
            confirmPasswordeye.classList.remove("fa-eye-slash");
        } else if (password_input2.type == "text") {
            password_input2.type = "password";
            confirmPasswordeye.classList.add("fa-eye-slash");
            confirmPasswordeye.classList.remove("fa-eye");
        }
    });
    $("#password_input").keyup(function () {
        let pass = document.getElementById("password_input").value;
        let pass2 = document.getElementById("Confirmpassword").value;
        $(".pmsg").hide();
        if (pass == "" || pass == null && pass2 == "" || pass2 == null) {
            document.getElementById("registerButton").setAttribute("disabled", "disabled");
            document.getElementById("registerButton").classList.remove('active');
            document.getElementById("registerButton").classList.add('inactive');
        } else {
            if (pass == pass2) {
                document.getElementById("registerButton").removeAttribute("disabled");
                document.getElementById("registerButton").classList.remove('inactive');
                document.getElementById("registerButton").classList.add('active');
            } else {
                document.getElementById("registerButton").setAttribute("disabled", "disabled");
                document.getElementById("registerButton").classList.remove('active');
                document.getElementById("registerButton").classList.add('inactive');
            }
        }
        passStrength(pass);
    });
    $("#Confirmpassword").keyup(function () {
        let pass1 = document.getElementById("password_input").value;
        let pass2 = document.getElementById("Confirmpassword").value;
        if (pass1 == "" || pass1 == null) {
            $(".pmsg").fadeIn().text("Please enter new password.*");
            return false;
        } else {
            if (pass1 != "" || pass1 != null) {
                if (pass1 == pass2) {
                    document.getElementById("registerButton").removeAttribute("disabled");
                    document.getElementById("registerButton").classList.remove('inactive');
                    document.getElementById("registerButton").classList.add('active');
                } else {
                    document.getElementById("registerButton").setAttribute("disabled", "disabled");
                    document.getElementById("registerButton").classList.remove('active');
                    document.getElementById("registerButton").classList.add('inactive');
                }
            } else {
                document.getElementById("registerButton").setAttribute("disabled", "disabled");
                document.getElementById("registerButton").classList.remove('active');
                document.getElementById("registerButton").classList.add('inactive');
            }
            $(".pmsg").hide();
        }
    });
   
    $('#registerButton').click(function (e) {
        e.preventDefault(0)
        let __firstname = $("input#firstname").val();
        let __lastname = $("input#lastname").val();
        let __email = $("input#email").val();
        let __password = $("input#password_input").val();
        let __confirmpassword = $("input#Confirmpassword").val();
        if (__firstname == "") {
            $(".fmsg").fadeIn().text("Please enter your firstname.*");
            $("input#firstname").focus();
            return false;
        }
        if (__lastname == "") {
            $(".lmsg").fadeIn().text("Please enter your lastname.*");
            $("input#lastname").focus();
            return false;
        }
        if (__email == "") {
            $(".emsg").fadeIn().text("Please enter your email.*");
            $("input#email").focus();
            return false;
        }
        if (__password == "") {
            $(".pmsg").fadeIn().text("Please enter your password.*");
            $("input#password_input").focus();
            return false;
        }
        if (__confirmpassword == "") {
            $(".cmsg").fadeIn().text("Please Re-type your password for confirmation.*");
            $("input#Confirmpassword").focus();
            return false;
        }
        if (__password !=__confirmpassword) {
            $(".cmsg").fadeIn().text("Both password are not the same*");
            $("input#Confirmpassword").focus();
            return false;
        }
        $(".emsg").hide()
        $('.base_error_msg_container').hide();
        // $(".loader").show();
        $(".loader").css("display", "inline-block");
        $(".text").text("Processing...");
        const data = { "firstname":__firstname, "lastname":__lastname, "email": __email, "password": __password,"confirmpassword":__confirmpassword };
        $.ajax({
            type: 'POST', // define the type of HTTP verb we want to use (POST for our form)
            dataType: 'JSON',
            contentType: "application/json; charset=utf-8",
            data: JSON.stringify(data), // our data object
            url: '/auth/register',
            processData: false,
            encode: true,
            crossOrigin: true,
            async: true,
            crossDomain: true,
            headers: {'Content-Type': 'application/json', "X-Requested-With": "XMLHttpRequest",},
        }).then((response) => {
            //user is logged in successfully in the back-end
            if (response.status == 200) {
                setTimeout(function () {
                    window.location.replace("/login");
                }, 0);
            } 
        }).fail((xhr, error) => {
            var catch_error = xhr.responseJSON
            if (catch_error.status == 409) {
                $(".loader").css("display", "none");
                $(".text").text("Sign Up");
                $('.emsg').empty();
                $('.emsg').show().text(catch_error.error);
                $('.base_error_msg_container').show();
                $('.alert__message').show().text(catch_error.error);
                $("input#email").focus();
            return false;
            } else if (catch_error.status == 406) {
                $('.cmsg').empty();
                $('.cmsg').show().text(catch_error.error);
                $(".loader").css("display", "none");
                $(".text").text("Sign Up");
            }else if (catch_error.status == 403 || catch_error.status == 405) {
                $('.base_error_msg_container').show();
                $('.alert__message').show().text(catch_error.error);
                $(".loader").css("display", "none");
                $(".text").text("Sign Up");
            }
        });
    });

    $('#loginButton').click(function (e) {
        e.preventDefault(0)
        $('.base_error_msg_container').hide();
        let __email = $("input#email").val();
        let __password = $("input#login_password_input").val();
       
        if (__email == "") {
            $(".emsg").fadeIn().text("Please enter your email.*");
            $(".pmsg").hide();
            $("input#email").focus();
            return false;
        }
        if (__password == "") {
            $(".emsg").hide()
            $(".pmsg").fadeIn().text("Please enter your password.*");
            $("input#login_password_input").focus();
            return false;
        }
        
        if (__email !="" || __email !=null && __password !="" && __password !=null) {
            const data = { "email": __email, "password": __password };
            // 
            $(".loader").show();
            $(".text").text("Logging in");
            $(".emsg").hide()
            $(".pmsg").hide()
            // 
            $.ajax({
                type: 'POST', // define the type of HTTP verb we want to use (POST for our form)
                dataType: 'JSON',
                contentType: "application/json; charset=utf-8",
                data: JSON.stringify(data), // our data object
                url: '/auth/login',
                processData: false,
                encode: true,
                crossOrigin: true,
                async: true,
                crossDomain: true,
                headers: {'Content-Type': 'application/json', "X-Requested-With": "XMLHttpRequest",},
            }).then((response) => {
                //user is logged in successfully in the back-end
                if (response.status == 200) {
                    setTimeout(function () {
                        window.location.replace("/");
                    }, 0);
                } else {
                    if (response.status == 409 || response.status == 406 || response.status == 403 || response.status == 405) {
                        $('.emsg').empty();
                        $('.pmsg').hide();
                        $(".loader").hide();
                        $(".text").text("Login");
                        $('.base_error_msg_container').show();
                        $('.alert__message').show().text(response.error);
                        $("input#email").focus();
                        return false;
                    }
                    $(".loader").hide();
                    $(".text").text("Login");
                }
            }).fail((xhr, error) => {
                var catch_error = xhr.responseJSON
                if (catch_error.status == 409 || catch_error.status == 406 || catch_error.status == 403 || catch_error.status == 405) {
                    $('.emsg').empty();
                    $('.pmsg').hide();
                    $(".loader").hide();
                    $(".text").text("Login");
                    $('.base_error_msg_container').show();
                    $('.alert__message').show().text(catch_error.error);
                    $("input#email").focus();
                    return false;
                } 
            });
        }
    });
});
