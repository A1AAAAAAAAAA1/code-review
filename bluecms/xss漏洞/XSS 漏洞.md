# XSS 漏洞

漏洞位置 user.php 修改个人账户信息模块

```
//编辑个人资料
 elseif($act == 'edit_user_info'){
	 $user_id = intval($_SESSION['user_id']);
	 if(empty($user_id)){
		 return false;
	 }
	$birthday = trim($_POST['birthday']);
	$sex = intval($_POST['sex']);
    $email = !empty($_POST['email']) ? trim($_POST['email']) : '';
    $msn = !empty($_POST['msn']) ? trim($_POST['msn']) : '';
    $qq = !empty($_POST['qq']) ? trim($_POST['qq']) : '';
    $mobile_phone = !empty($_POST['mobile_phone']) ? trim($_POST['mobile_phone']) : '';
    $office_phone = !empty($_POST['office_phone']) ? trim($_POST['office_phone']) : '';
    $home_phone   = !empty($_POST['home_phone']) ? trim($_POST['home_phone']) : '';
	$address = !empty($_POST['address']) ? htmlspecialchars($_POST['address']) : '';
```

可以看到，对我们传入的这些参数，除了$address，其他参数都没有htmlspecialchars，intval等函数进行限制，所以这些字符都可以进行一个xss。 但是，由于数据中字段长度有限制，所以存在xss的点只有，$msn和$email处。



添加功能处XSS

```
elseif ($act == 'do_add_news') {
 	include_once 'include/upload.class.php';
 	$image = new upload();
 	$title = !empty($_POST['title']) ? htmlspecialchars(trim($_POST['title'])) : '';
 	$color = !empty($_POST['color']) ? htmlspecialchars(trim($_POST['color'])) : '';
 	$cid = !empty($_POST['cid']) ? intval($_POST['cid']) : '';
 	if(empty($cid)){
 		showmsg('新闻分类不能为空');
 	}
 	$author = !empty($_POST['author']) ? htmlspecialchars(trim($_POST['author'])) : $_SESSION['admin_name'];
 	$source = !empty($_POST['source']) ? htmlspecialchars(trim($_POST['source'])) : '';
	$content = !empty($_POST['content']) ? filter_data($_POST['content']) : '';
	$descript = !empty($_POST['descript']) ? mb_substr($_POST['descript'], 0, 90) : mb_substr(html2text($_POST['content']),0, 90);
 	if(isset($_FILES['lit_pic']['error']) && $_FILES['lit_pic']['error'] == 0){
		$lit_pic = $image->img_upload($_FILES['lit_pic'],'lit_pic');
	}

```

```
function filter_data($str)

{

	$str = preg_replace("/<(\/?)(script|i?frame|meta|link)(\s*)[^<]*>/", "", $str);

	return $str;

}
```



