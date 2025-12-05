/*
var btnUpload = $("#upload_file"),
    btnOuter = $(".button_outer");

btnUpload.on("change", function (e) {
    var ext = btnUpload.val().split('.').pop().toLowerCase();
    if ($.inArray(ext, ['gif', 'png', 'jpg', 'jpeg', 'pcap']) == -1) {
        $(".error_msg").text("Invalid file format...");
    } else {
        $(".error_msg").text("");
        btnOuter.addClass("file_uploading");
        setTimeout(function () {
            btnOuter.addClass("file_uploaded");
        }, 3000);
        var uploadedFile = URL.createObjectURL(e.target.files[0]);
        setTimeout(function () {
            $("#uploaded_view").append('<img src="' + uploadedFile + '" />').addClass("show");
        }, 3500);
    }
});

*/
/*

$(".file_remove").on("click", function (e) {
    $("#uploaded_view").removeClass("show");
    $("#uploaded_view").find("img").remove();
    btnOuter.removeClass("file_uploading");
    btnOuter.removeClass("file_uploaded");
});
*/

window.addEventListener('load', function(){
    submit_click()
})

function submit_click(){
    var e = document.getElementsByClassName("text-secondary font-weight-bold text-xs submit-button")
    for (var i = 0; i < e.length; i++) {
        e[i].addEventListener('click', function () {
                // Lấy id của nút được click và gán vào biến dataset_name

                var dataset_name = $(this).attr('id');
                // Gửi yêu cầu AJAX với dataset_name
                $.ajax({
                    type: 'POST',
                    url: '/test',
                    data: {
                        dataset_name: dataset_name
                    },
                    success: function(response) {
                        if(response == 1){
                            Swal.fire({
                                title: 'Phát hiện tấn công!!',
                                text: "Luồng dữ liệu độc hại!",
                                icon: 'warning',
                                showCancelButton: true,
                                confirmButtonText: 'Chi tiết!',
                                cancelButtonText: 'Ok!',
                                reverseButtons: true
                                }).then((result) => {
                                    if (result.isConfirmed) {
                                        var dataset_name_2 = dataset_name; 
                                        redirectToDetailsPage(dataset_name_2);

                                    } else if (result.dismiss === Swal.DismissReason.cancel) {
                                        window.location.href = '/tables'
                                    }
                                  })
                        }
                        else{
                            Swal.fire({
                                title: 'Bình thường!!',
                                text: "Luồng dữ liệu lành tính!",
                                icon: 'success',
                                showCancelButton: false,
                                confirmButtonText: 'OK!',
                                reverseButtons: true
                                }).then((result) => {
                                    if (result.isConfirmed) {
                                        window.location.href = '/tables'
                                    } 
                                  })
                        }
                    
                        // Thực hiện lệnh JavaScript sau khi nhận được giá trị a
                        
                        // Thực hiện chuyển hướng đến route "/tables" trong Flask
                        
                    },
                    error: function(error) {
                        console.error(error);
                    }
                }); 
        })
    }
}

function redirectToDetailsPage(dataset_name) {
    // Tạo một biểu mẫu ẩn
    var form = document.createElement("form");
    form.method = "post";
    form.action = "/details";

    // Tạo một input ẩn để truyền dữ liệu
    var input = document.createElement("input");
    input.type = "hidden";
    input.name = "flow_name";
    input.value = dataset_name;

    // Thêm input vào biểu mẫu
    form.appendChild(input);

    // Thêm biểu mẫu vào trang và tự động gửi yêu cầu
    document.body.appendChild(form);
    form.submit();
}


window.addEventListener('load', function(){
    upload_file_to_flows()
})

function upload_file_to_flows(){
    var e = document.getElementById("upload_file")
    if(e){
        e.addEventListener('change', function (){
            var selected_file = e.files[0]
            var full_file_name = selected_file.name.toString()
            $.ajax({
                type: 'POST',
                url: '/upload_file_to_flows',
                data: {
                    a: full_file_name
                },
                success: function(response) {
                    if(response.toString() == "1"){
                        Swal.fire({
                            title: 'Thành công!!',
                            text: "Upload flow dữ liệu thành công!",
                            icon: 'success',
                            showCancelButton: false,
                            confirmButtonText: 'OK!',
                            reverseButtons: true
                            }).then((result) => {
                                if (result.isConfirmed) {
                                    window.location.href = '/tables'
                                } 
                              })
                    }
                    else{
                        Swal.fire(
                            'Không thành công!',
                            'Flow đã tồn tại!',
                            'warning'
                          );
                    }
    
                },
                error: function(error) {
                    console.log("error");
                }
            }); 
        })
    }
    
}

window.addEventListener('load', function(){
    capture_button_listen()
})

function capture_button_listen(){
    var e = document.getElementById("captureButton")
    if (e){
        e.addEventListener('click', function(){
            var selectElement = document.getElementById("inputGroupSelect01");
            var selectedValue = selectElement.value;
            $.ajax({
                type: 'POST',
                url: '/capture_extract',
                data: {
                    interface_name: selectedValue
                },
                success: function(response) {
    
                },
                error: function(error) {
                    console.log("error");
                }
            }); 
        })
    }

}
/*
window.addEventListener('load', function(){
    upload_file_to_check_virus()
})
function upload_file_to_check_virus(){
    var e = document.getElementById("virus_check_file");
    e.addEventListener('change', function (){
        var selected_file = e.files[0];
        var full_file_name = selected_file.name.toString();

        // Tạo một hidden input để chứa tên file
        var hiddenInput = document.createElement('input');
        hiddenInput.type = 'hidden';
        hiddenInput.name = 'a';  // Tên field mà bạn sẽ sử dụng trong Flask để lấy dữ liệu
        hiddenInput.value = full_file_name;

        // Tìm form để thêm hidden input vào
        var form = document.createElement('form');
        form.method = 'POST';
        form.action = '/ip_upload';

        // Thêm hidden input vào form
        form.appendChild(hiddenInput);

        // Gửi form tự động
        document.body.appendChild(form);  // Thêm form vào body để có thể gửi đi
        form.submit();
    });
}

*/
window.addEventListener('load', function(){
    var fileInput = document.getElementById("virus_check_file");
    var uploadButton = document.getElementById("ioc_button");
    if (uploadButton){
        uploadButton.addEventListener('click', function(){
            upload_file_to_check_virus(fileInput);
        });
    }
});


function upload_file_to_check_virus(fileInput){
    var selected_file = fileInput.files[0];
    if (!selected_file) {
        Swal.fire({
            title: "Chưa chọn file!",
            text: "Hãy chọn file ip cần check!",
            icon: "warning"
        });
        return;
    }

    // Sử dụng FileReader để đọc nội dung file
    var reader = new FileReader();
    reader.onload = function(e) {
        var fileContent = e.target.result;
        var ipArray = fileContent.split(/\r?\n/).filter(Boolean); 

        var ipArrayJSON = JSON.stringify(ipArray);

        var hiddenInput = document.createElement('input');
        hiddenInput.type = 'hidden';
        hiddenInput.name = 'ip_list';  
        hiddenInput.value = ipArrayJSON;

        var form = document.createElement('form');
        form.method = 'POST';
        form.action = '/ip_upload_2';

        // Thêm hidden input vào form
        form.appendChild(hiddenInput);

        // Thêm form vào body và tự động submit
        document.body.appendChild(form);
        form.submit();

        // Xóa form sau khi submit để tránh tạo nhiều form không cần thiết
        document.body.removeChild(form);
    };

    // Đọc file dưới dạng text
    reader.readAsText(selected_file);
}

/*
function upload_file_to_check_virus(fileInput){
    var selected_file = fileInput.files[0];
    if (!selected_file) {
        Swal.fire({
            title: "Chưa chọn file!",
            text: "Hãy chọn file ip cần check!",
            icon: "warning"
        });
        return;
    }

    var reader = new FileReader();
    reader.onload = function(e) {
        var fileContent = e.target.result;
        var ipArray = fileContent.split(/\r?\n/).filter(Boolean); 
        console.log(ipArray);
        sendDataToBackend(ipArray);
    };

    // Đọc file dưới dạng text
    reader.readAsText(selected_file);
}

function sendDataToBackend(ipArray) {
    // Sử dụng fetch để gửi mảng địa chỉ IP qua backend
    fetch('/ip_upload_2', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip_list: ipArray }), // Gửi dưới dạng JSON
    });
}
*/

/*
function upload_file_to_check_virus(){
    var e = document.getElementById("virus_check_file")
    e.addEventListener('change', function (){
        var selected_file = e.files[0]
        var full_file_name = selected_file.name.toString()
        $.ajax({
            type: 'POST',
            url: '/ip_upload',
            data: {
                a: full_file_name
            },
            success: function(response) {
                console.log("print")
            },
            error: function(error) {
                console.log("error");
            }
        }); 
    })
}

*/

window.addEventListener('load', function(){
    end_button_click()
})

function end_button_click(){
    var e = document.getElementById("end_button")
    if (e){
       e.addEventListener('click', function (){
        $.ajax({
            type: 'POST',
            url: '/end',
            data: {
                interface_name: "a"
            },
            success: function(response) {
                Swal.fire({
                    title: "Kết thúc!",
                    text: "Đã dừng việc giám sát!",
                    icon: "success"
                  });
            },
            error: function(error) {
                console.log("error");
            }
        }); 
    })     
    }
}

window.addEventListener('load', function(){
    start_button_click()
})

function start_button_click(){
    var e = document.getElementById("start_button")
    if(e){
        e.addEventListener('click', function (){
            $.ajax({
                type: 'POST',
                url: '/start',
                data: {
                    interface_name: "a"
                },
                success: function(response) {
                    console.log(response)
                    if (response == '1'){
                        Swal.fire({
                            title: "Bắt đầu!",
                            text: "Bắt đầu hoạt động giám sát!",
                            icon: "success"
                          });
                    }
                    else{
                        Swal.fire({
                            title: "Lỗi!",
                            text: "Hệ thống đang thực hiện giám sát!",
                            icon: "error"
                          });
                    }
    
                        
                },
                error: function(error) {
                    console.log("error");
                }
            }); 
        })
    }
}


window.addEventListener('load', function(){
    sign_in_button_listener_3()
})


function sign_in_button_listener_2() {
    var e = document.getElementById("sign_in_button");
    if (e){
        e.addEventListener('click', function () {
            const email = document.querySelector('input[aria-label="Email"]').value;
            const password = document.querySelector('input[aria-label="Password"]').value;
            if (email === "" || password === "") {
                Swal.fire({
                    title: "Nhập thông tin!",
                    text: "Nhập đầy đủ thông tin đăng nhập!",
                    icon: "warning" 
                });
            } else {
                $.ajax({
                    type: 'POST',
                    url: '/sign_in',
                    data: {
                        email: email,
                        password: password
                    },
                    success: function (response) {
                        if (response == '0'){
                            Swal.fire({
                                title: "Đăng nhập thất bại!",
                                text: "Thông tin đăng nhập không chính xác!",
                                icon: "warning"
                            });
                        } else{
                            window.location.href = '/index'
                        }
    
    
                    },
                    error: function (error) {
                        console.log("error");
                    }
                });
            }
        });
    }
}


function sign_in_button_listener_3(){
    var e = document.getElementById('sign_in_button')
    if (e){
        e.addEventListener('click', function () {
            const email = document.querySelector('input[aria-label="Email"]').value;
            const password = document.querySelector('input[aria-label="Password"]').value;
    
            if (email === "" || password === "") {
                Swal.fire({
                    title: "Nhập thông tin!",
                    text: "Hãy nhập đầy đủ email và mật khẩu",
                    icon: "warning"
                });
                return;
            }
            fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `email=${email}&password=${password}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    Swal.fire({
                        title: "Thành công!",
                        text: data.message,
                        icon: "success"
                    }).then(() => {
                        window.location.href = "/index";  // Chuyển hướng đến trang được bảo vệ
                    });
                } else {
                    Swal.fire({
                        title: "Lỗi!",
                        text: data.message,
                        icon: "error"
                    });
                }
            })
            .catch(error => console.log('Error:', error));
        });
    }
}


window.addEventListener('load', function(){
    logout_listener()
})

function logout_listener(){
    var e = document.getElementById('logout_button')
    if (e){
        e.addEventListener('click', function () {
        fetch('/logout', {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                Swal.fire({
                    title: "Thành công!",
                    text: data.message,
                    icon: "success"
                }).then(() => {
                    window.location.href = "/";  // Chuyển hướng đến trang được bảo vệ
                });
            } else {
                Swal.fire({
                    title: "Lỗi!",
                    text: "Có lỗi xảy ra khi đăng xuất",
                    icon: "error"
                });
            }
        })
        .catch(error => console.log('Error:', error));
    });
    }

}


window.addEventListener('load', function(){
    update_button()
})


function update_button() {

    var e = document.getElementById("update_button");
    if(e){
        e.addEventListener('click', function () {
            // Lấy nội dung từ textarea
            var textareaContent = document.getElementById('blacklist-textbox-update').value;
            console.log('Nhật')
            console.log(textareaContent)
            // Chuyển nội dung thành mảng, mỗi dòng là một phần tử
            var ipArray = textareaContent.split('\n').map(ip => ip.trim()).filter(ip => ip !== '');
        
            // Kiểm tra nếu textarea trống
            if (ipArray.length === 0) {
                Swal.fire({
                title: "Chưa nhập IP!",
                text: "Hãy nhập danh sách IP cần cập nhật!",
                icon: "warning"
                });
                return;
            }
        
            // Chuyển mảng IP thành JSON string
            var ipArrayJSON = JSON.stringify(ipArray);
        
            // Lấy giá trị và chỉ số của select box
            var selectBox = document.getElementById('color-select');
            var selectedList = selectBox.value;
            var selectedIndex = selectBox.selectedIndex;
        
            // Tạo các input ẩn để chứa dữ liệu
            var listTypeInput = document.createElement('input');
            listTypeInput.type = 'hidden';
            listTypeInput.name = 'listType';
            listTypeInput.value = selectedList;
        
            var listIndexInput = document.createElement('input');
            listIndexInput.type = 'hidden';
            listIndexInput.name = 'listIndex';
            listIndexInput.value = selectedIndex;
        
            var ipListInput = document.createElement('input');
            ipListInput.type = 'hidden';
            ipListInput.name = 'ips';
            ipListInput.value = ipArrayJSON;
        
            // Tạo form và thêm các input ẩn vào
            var form = document.createElement('form');
            form.method = 'POST';
            form.action = '/update_list';
        
            form.appendChild(listTypeInput);
            form.appendChild(listIndexInput);
            form.appendChild(ipListInput);
        
            // Thêm form vào body và tự động submit
            document.body.appendChild(form);
            form.submit();
        
            // Xóa form sau khi submit để tránh tạo nhiều form không cần thiết
            document.body.removeChild(form);
             
        });
    }
}

window.addEventListener('load', function () {
    search_history_button()
})

function search_history_button() {
    var e = document.getElementById("search_history_button");
    if (!e) return;

    e.addEventListener('click', function () {
        var datetime1 = document.getElementById("datetimepicker_1").value;
        var datetime2 = document.getElementById("datetimepicker_2").value;

        if (datetime1 === '' || datetime2 === '') {
            Swal.fire({
                title: "Chưa nhập ngày!",
                text: "Hãy nhập đầy đủ ngày tháng.",
                icon: "warning"
            });
            return;
        }

        Swal.fire({
            title: "Đang tìm kiếm...",
            html: "Vui lòng đợi trong giây lát.",
            allowOutsideClick: false,
            allowEscapeKey: false,
            didOpen: () => Swal.showLoading()
        });

        $.ajax({
            type: 'POST',
            url: '/search_history',
            data: {
                date_1: datetime1,
                date_2: datetime2,
            },
            success: function (response) {

                // --- IF COUNT == 0 ---
                if (response.count === 0) {

                    Swal.fire({
                        title: "Không tìm thấy bản ghi!",
                        html: "Hệ thống sẽ hiển thị lại toàn bộ log giám sát.",
                        icon: "info",
                        timer: 1500,
                        showConfirmButton: false
                    }).then(() => {

                        // Gọi API reset search để không vào search_mode
                        fetch('/reset_search', {
                            method: 'POST'
                        }).finally(() => {
                            window.location.href = "/monitor";
                        });

                    });

                } else {
                    // --- IF COUNT > 0 ---
                    Swal.fire({
                        title: "Kết quả",
                        html: `<b>${response.count}</b> bản ghi được tìm thấy.`,
                        icon: "success",
                        timer: 1500,
                        showConfirmButton: false
                    }).then(() => {
                        window.location.href = "/monitor";
                    });
                }
            },

            error: function () {
                Swal.fire({
                    title: "Lỗi!",
                    text: "Có lỗi xảy ra khi tìm kiếm.",
                    icon: "error"
                });
            }
        });
    });
}


function chart_2(){
    var ctx = document.getElementById("chartLinePurple_2").getContext("2d");

    var gradientStroke = ctx.createLinearGradient(0, 230, 0, 50);

    gradientStroke.addColorStop(1, 'rgba(29,140,248,0.2)');
    gradientStroke.addColorStop(0.4, 'rgba(29,140,248,0.0)');
    gradientStroke.addColorStop(0, 'rgba(29,140,248,0)'); //blue colors
    

    var myChart = new Chart(ctx, {
      type: 'horizontalBar',
      responsive: true,
      legend: {
        display: false
      },
      data: {
        labels: ['China APT Group', 'MageCart Group 9', 'UNC4191', 'RATicate', 'Haskers Gang', 'TiltedTemple'],
        datasets: [{
          label: "Countries",
          fill: true,
          backgroundColor: gradientStroke,
          hoverBackgroundColor: gradientStroke,
          borderColor: '#1f8ef1',
          borderWidth: 2,
          borderDash: [],
          borderDashOffset: 0.0,
          data: [53, 20, 10, 80, 100, 45],
        }]
      },
      options: gradientBarChartConfiguration
    });
}

function chart(){
    var ctx = document.getElementById("CountryChart").getContext("2d");

    var gradientStroke = ctx.createLinearGradient(0, 230, 0, 50);

    gradientStroke.addColorStop(1, 'rgba(29,140,248,0.2)');
    gradientStroke.addColorStop(0.4, 'rgba(29,140,248,0.0)');
    gradientStroke.addColorStop(0, 'rgba(29,140,248,0)'); //blue colors
    

    var myChart = new Chart(ctx, {
      type: 'bar',
      responsive: true,
      legend: {
        display: false
      },
      data: {
        labels: ['USA', 'GER', 'AUS', 'UK', 'RO', 'BR'],
        datasets: [{
          label: "Countries",
          fill: true,
          backgroundColor: gradientStroke,
          hoverBackgroundColor: gradientStroke,
          borderColor: '#1f8ef1',
          borderWidth: 2,
          borderDash: [],
          borderDashOffset: 0.0,
          data: [53, 20, 10, 80, 100, 45],
        }]
      },
      options: gradientBarChartConfiguration
    });
}


window.addEventListener('load', function(){
    click_pagination_1()
})

function click_pagination_1(){
    let pageLinks = document.querySelectorAll(".page-link.ioc");

        pageLinks.forEach(link => {
            link.addEventListener("click", function(event) {
                event.preventDefault(); 
                pageNumber = this.id.replace("page_", "");
                window.location.href = `/ioc_page?page=${pageNumber}`;
            });
        });
}


window.addEventListener('load', function(){
    click_pagination_monitor()
})

function click_pagination_monitor(){
    let pageLinks = document.querySelectorAll(".page-link.nhat");

        pageLinks.forEach(link => {
            link.addEventListener("click", function(event) {
                event.preventDefault(); 
                pageNumber = this.id.replace("page_", "");
                window.location.href = `/monitor_page?page=${pageNumber}`;
            });
        });
}

window.addEventListener('load', function(){
    add_ioc_button()
})


function add_ioc_button() {
    var addButton = document.getElementById("add_ioc_button");
    if (addButton) {
        addButton.addEventListener("click", function () {
            console.log("Nhật - Đang gửi dữ liệu");

            //var idValue = document.getElementById("id-input").value.trim();
            var urlValue = document.getElementById("url-input").value.trim();
            var descriptionValue = document.getElementById("description-input").value.trim();
            var statusValue = document.getElementById("status-select").value;
            var threatValue = document.getElementById("threat-select").value;
            var patternValue = document.getElementById("pattern-input").value.trim();
            var validFromValue = document.getElementById("valid-from").value;
            var validUntilValue = document.getElementById("valid-until").value;

            if (!urlValue ) {
                Swal.fire({
                    title: "Thiếu dữ liệu!",
                    text: "ID, C&C không được để trống.",
                    icon: "warning"
                });
                return;
            }

            var formData = {
                //id: idValue,
                url: urlValue,
                description: descriptionValue,
                status: statusValue,
                threat: threatValue,
                pattern: patternValue,
                valid_from: validFromValue,
                valid_until: validUntilValue
            };

            // Gửi dữ liệu qua AJAX (Fetch API)
            fetch("/add_ioc", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(formData)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    Swal.fire({
                        title: "Thành công!",
                        text: "Mối đe dọa đã được thêm.",
                        icon: "success"
                    }).then(() => {
                        location.reload(); // Refresh trang sau khi thêm thành công
                    });
                } else {
                    Swal.fire({
                        title: "Lỗi!",
                        text: data.message || "Có lỗi xảy ra khi thêm mối đe dọa.",
                        icon: "error"
                    });
                }
            })
            .catch(error => {
                console.error("Lỗi gửi dữ liệu:", error);
                Swal.fire({
                    title: "Lỗi!",
                    text: "Không thể kết nối đến server.",
                    icon: "error"
                });
            });
        });
    }
}


window.addEventListener('load', function(){
    add_user()
})


function add_user() {
    var addButton = document.getElementById("add_user_button");
    if (addButton) {
        addButton.addEventListener("click", function () {
            console.log("Nhật - Đang gửi dữ liệu");

            var username = document.getElementById("username-input").value.trim();
            var password = document.getElementById("password-input").value.trim();
            var unit = document.getElementById("unit-input").value.trim();
            var role = document.getElementById("role-select").value;
            if (!username || !password || !unit || !role) {
                Swal.fire({
                    title: "Thiếu dữ liệu!",
                    text: "Các trường thông tin không được để trống.",
                    icon: "warning"
                });
                return;
            }

            var formData = {
                username: username,
                password: password,
                unit: unit,
                role: role
            };

            // Gửi dữ liệu qua AJAX (Fetch API)
            fetch("/add_user", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(formData)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    Swal.fire({
                        title: "Thành công!",
                        text: "Đã tạo mới người dùng.",
                        icon: "success"
                    }).then(() => {
                        location.reload(); // Refresh trang sau khi thêm thành công
                    });
                } else {
                    Swal.fire({
                        title: "Lỗi!",
                        text: data.message || "Có lỗi xảy ra khi tạo người dùng.",
                        icon: "error"
                    });
                }
            })
            .catch(error => {
                console.error("Lỗi gửi dữ liệu:", error);
                Swal.fire({
                    title: "Lỗi!",
                    text: "Không thể kết nối đến server.",
                    icon: "error"
                });
            });
        });
    }
}

window.addEventListener('load', function(){
    delete_user()
})


function delete_user() {
    var delButtons = document.querySelectorAll(".icon-trash-simple"); // Lấy tất cả icon
    
    delButtons.forEach(delButton => { 
        delButton.addEventListener("click", function() {
            var username = delButton.id.trim();
            var formData = {
                username: username
            };
            fetch("/delete_user", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(formData)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    Swal.fire({
                        title: "Thành công!",
                        text: "Đã xóa người dùng " + username,
                        icon: "success"
                    }).then(() => {
                        location.reload(); // Refresh trang sau khi thêm thành công
                    });
                } else {
                    Swal.fire({
                        title: "Lỗi!",
                        text: data.message || "Có lỗi xảy ra khi xóa người dùng.",
                        icon: "error"
                    });
                }
            })
            .catch(error => {
                console.error("Lỗi gửi dữ liệu:", error);
                Swal.fire({
                    title: "Lỗi!",
                    text: "Không thể kết nối đến server.",
                    icon: "error"
                });
            });
        });
    });
}


// Thanh phân trang cho trang quản lý người dùng


function click_pagination_user_managerment(){
    let pageLinks = document.querySelectorAll(".page-link.user_managerment");

        pageLinks.forEach(link => {
            link.addEventListener("click", function(event) {
                event.preventDefault(); 
                pageNumber = this.id.replace("page_", "");
                window.location.href = `/user_managerment_page?page=${pageNumber}`;
            });
        });
}
window.addEventListener('load', function(){
    click_pagination_user_managerment()
})
// Thanh phân trang cho trang quản lý người dùng
window.addEventListener('load', function(){
    click_pagination_search_and_backup()
})

function click_pagination_search_and_backup(){
    let pageLinks = document.querySelectorAll(".page-link.search_and_backup");

        pageLinks.forEach(link => {
            link.addEventListener("click", function(event) {
                event.preventDefault(); 
                pageNumber = this.id.replace("page_", "");
                window.location.href = `/search_and_backup_page?page=${pageNumber}`;
            });
        });
}



window.addEventListener("load", function () {
    export_button();
});

function export_button() {
    const exportBtn = document.getElementById("export_button");
    if (exportBtn) {
        exportBtn.addEventListener("click", function () {
            console.log("Nhật - Đang xuất dữ liệu...");

            fetch("/export_file")
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        const blob = new Blob(
                            [JSON.stringify(data.data, null, 2)],
                            { type: "application/json" }
                        );

                        const now = new Date();
                        const timestamp = now.toISOString().replace(/[:.]/g, "-");
                        const filename = `mongo_export_${timestamp}.json`;

                        const link = document.createElement("a");
                        link.href = URL.createObjectURL(blob);
                        link.download = filename;
                        document.body.appendChild(link);
                        link.click();
                        document.body.removeChild(link);

                        Swal.fire({
                            title: "Thành công!",
                            text: data.message,
                            icon: "success"
                        });
                    } else {
                        Swal.fire({
                            title: "Lỗi!",
                            text: data.message || "Không thể xuất dữ liệu.",
                            icon: "error"
                        });
                    }
                })
                .catch(error => {
                    console.error("Lỗi khi xuất dữ liệu:", error);
                    Swal.fire({
                        title: "Lỗi!",
                        text: "Không thể kết nối đến server.",
                        icon: "error"
                    });
                });
        });
    }
}


window.addEventListener("load", function () {
    import_file();
});
function import_file() {
    const fileInput = document.getElementById("jsonFile");
    if (fileInput) {
      fileInput.addEventListener("change", async function () {
        const file = fileInput.files[0];
  
        if (!file) {
          Swal.fire({
            title: "Chưa chọn file!",
            text: "Vui lòng chọn file JSON để nhập.",
            icon: "warning"
          });
          return;
        }
  
        const formData = new FormData();
        formData.append("file", file);
  
        try {
          const response = await fetch("/import_file", {
            method: "POST",
            body: formData
          });
  
          const result = await response.json();
  
          if (!response.ok || !result.success) {
            Swal.fire({
              title: "Lỗi!",
              text: result.message || "Không thể xử lý tệp dữ liệu.",
              icon: "error"
            });
          } else {
            Swal.fire({
              title: "Thành công!",
              text: `Đã import ${result.count} bản ghi.`,
              icon: "success"
            }).then(() => {
                location.href = "/search_and_backup";  
            });
          }
        } catch (error) {
          console.error("Lỗi import:", error);
          Swal.fire({
            title: "Lỗi kết nối!",
            text: error.message,
            icon: "error"
          });
        }
  
        fileInput.value = ""; // reset để có thể chọn lại file
      });
    }
  }

window.addEventListener("load", function () {
    search_button();
});
function search_button() {
    const searchBtn = document.getElementById("search_keyword_button");
    const searchInput = document.getElementById("search_textbox");
  
    if (searchBtn && searchInput) {
      searchBtn.addEventListener("click", async function () {
        const keyword = searchInput.value.trim();
        if (!keyword) {
          Swal.fire({
            title: "Thiếu từ khóa!",
            text: "Vui lòng nhập từ khóa để tìm kiếm.",
            icon: "warning"
          });
          return;
        }
  
        try {
          const response = await fetch('/search_keyword', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ keyword: keyword })
          });
  
          const result = await response.json();
  
          if (!response.ok || !result.success) {
            Swal.fire({
              title: "Lỗi!",
              text: result.message || "Không thể xử lý tìm kiếm.",
              icon: "error"
            });
          } else {
            Swal.fire({
              title: "Đã tìm kiếm!",
              text: result.message,
              icon: "success"
            }).then(() => {
                location.href = "/search_and_backup"; // ← Thêm dòng này để reload lại trang
            });
          }
        } catch (error) {
          console.error("Lỗi khi tìm kiếm:", error);
          Swal.fire({
            title: "Lỗi kết nối!",
            text: error.message,
            icon: "error"
          });
        }
      });
    }
  }

function click_pagination_login_event(){
    let pageLinks = document.querySelectorAll(".page-link.login-log");

        pageLinks.forEach(link => {
            link.addEventListener("click", function(event) {
                event.preventDefault(); 
                pageNumber = this.id.replace("page_", "");
                window.location.href = `/login_event_page?page=${pageNumber}`;
            });
        });
}
window.addEventListener('load', function(){
    click_pagination_login_event()
})
// Thanh phân trang cho trang quản lý người dùng
window.addEventListener('load', function(){
    click_pagination_search_and_backup()
})

