$(document).ready(function () {
    AOS.init();
    navbar()
    $(window).on("scroll", function () {
        navbar();
    })
    $(document).on("click", ".navbar-nav a", function () {
        $(this).addClass("active");
    })
    // $(document).on("click",".navbar .navbar-toggler",function () {
    //    $(".navbar-collapse").css("background-color", "white");
    //    $(".navbar-nav .nav-link").css("color", "black!important");
    // })

    $(document).on("click", "#all", function () {
        $(".one").removeClass("d-none");
        $(".two").removeClass("d-none");
        $(".three").removeClass("d-none");
        $(".four").removeClass("d-none");
        $(".five").removeClass("d-none");
        $(".six").removeClass("d-none");
    })
    $(document).on("click", "#branding", function () {
        $(".one").removeClass("d-none");
        $(".two").addClass("d-none");
        $(".three").removeClass("d-none");
        $(".four").addClass("d-none");
        $(".five").addClass("d-none");
        $(".six").addClass("d-none");
    })
    $(document).on("click", "#marketing", function () {
        $(".one").removeClass("d-none");
        $(".two").removeClass("d-none");
        $(".three").addClass("d-none");
        $(".four").addClass("d-none");
        $(".five").addClass("d-none");
        $(".six").addClass("d-none");
    })
    $(document).on("click", "#web", function () {
        $(".one").addClass("d-none");
        $(".two").addClass("d-none");
        $(".three").addClass("d-none");
        $(".four").removeClass("d-none");
        $(".five").addClass("d-none");
        $(".six").removeClass("d-none");
    })
    $(document).on("click", "#grapic", function () {
        $(".one").addClass("d-none");
        $(".two").removeClass("d-none");
        $(".three").addClass("d-none");
        $(".four").addClass("d-none");
        $(".five").removeClass("d-none");
        $(".six").addClass("d-none");
    })

    // $(document).on("mouseout", ".pages", function () {
    //     console.log("mouse out");

    //     $(".pages").addClass("d-none");
    // })
    // $("#pages-button").mouseover(function(){
    //     $(".pages").removeClass("d-none");

    //   });
    //   $("#pages-button").mouseout(function(){
    //     $(".pages").addClass("d-none");
    //   });
    $('.testimonial-carusel').owlCarousel({
        loop: true,
        margin: 20,
        items: 3,
        dots: true,
        responsive: {
            0: {
                items: 1
            },
            768: {
                items: 2
            },
            1024: {
                items: 3
            }
        }
    })
    function navbar() {
        if ($(window).scrollTop() > 30) {
            $(".navbar").addClass("scrolled","navbar-light")
            $(".navbar-brand img").attr("src", "/img/logoblack.svg");
            // let image="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 30 30'><path stroke='rgba%280, 0, 0, 0.55%29' stroke-linecap='round' stroke-miterlimit='10' stroke-width='2' d='M4 7h22M4 15h22M4 23h22'/></svg>";
            $(".navbar-toggler-icon").css("background-color", "#081828");
            $(".scroll-top").css({ opacity: 1 });
            
        }
        else {
            $(".navbar").removeClass("scrolled")
            $(".navbar-brand img").attr("src", "/img/logo.svg")
            $(".scroll-top").css({ opacity: 0 });


        }
    }
    

});