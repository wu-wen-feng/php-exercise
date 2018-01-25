<?php
// +----------------------------------------------------------------------
// | KXT [ No pains,no gains. ]
// +----------------------------------------------------------------------
// | Copyright (c) 2017-2027 http://kxt.com All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: yourname <yourqqnumber@qq.com>
// +----------------------------------------------------------------------
// | Description: 首页
// +----------------------------------------------------------------------
namespace app\home\controller;

include_once VENDOR_PATH . 'aliyun/aliyun-php-sdk-core/Config.php';
include_once VENDOR_PATH . 'aliyuncs/oss-sdk-php/autoload.php';

use Mts\Request\V20140618 as Mts;
use DefaultAcsClient;
use DefaultProfile;
//use think\console\command\make\Controller;
use think\Controller;
use Think\Exception;

use OSS\OssClient;
use OSS\Core\OssUtil;
use OSS\Core\OssException;

class Test extends Controller
{
    private $OSS_KEYID = '';
    private $OSS_SECRET = '';
    private $OSS_ENDPOINT = 'http://oss-cn-hangzhou.aliyuncs.com';
    private $OSS_BUCKET = 'convert-test';
    private $FILE_NAME = '';


    public function upload()
    {
        return $this->Fetch();
    }

    public function get()
    {
        /*$id = '6MKOqxGiGU4AUk44';
        $key = 'ufu7nS8kS59awNihtjSonMETLI0KLy';
        $host = 'http://post-test.oss-cn-hangzhou.aliyuncs.com';
        $callbackUrl = "http://oss-demo.aliyuncs.com:23450";*/
        $id = $this->OSS_KEYID;
        $key = $this->OSS_SECRET;
        $host = 'http://convert-test.oss-cn-hangzhou.aliyuncs.com';
        $callbackUrl = "http://adi.kuaixun56.com/test/callback";
        $vid = input("vid", 1);
        $callback_param = array(
            'callbackUrl' => $callbackUrl,
            'callbackBody' => 'vid=' . $vid . '&filename=${object}&size=${size}&mimeType=${mimeType}&height=${imageInfo.height}&width=${imageInfo.width}',
            //'callbackBody' => "filename=${object}&size=${size}&mimeType=${mimeType}&height=${imageInfo.height}&width=${imageInfo.width}",
            //'callbackBodyType' => "application/x-www-form-urlencoded");
            'callbackBodyType' => "application/json");
        $callback_string = json_encode($callback_param);

        $base64_callback_body = base64_encode($callback_string);
        $now = time();
        //$expire = 3000; //设置该policy超时时间是10s. 即这个policy过了这个有效时间，将不能访问
        $expire = 3000000; //设置该policy超时时间是10s. 即这个policy过了这个有效时间，将不能访问
        $end = $now + $expire;
        $expiration = $this->gmt_iso8601($end);

        $dir = 'user-dir/';  //oss中bucket下的目录，可以设置

        //最大文件大小.用户可以自己设置
        $condition = array(0 => 'content-length-range', 1 => 0, 2 => 1048576000);
        $conditions[] = $condition;

        //表示用户上传的数据,必须是以$dir开始, 不然上传会失败,这一步不是必须项,只是为了安全起见,防止用户通过policy上传到别人的目录
        $start = array(0 => 'starts-with', 1 => '$key', 2 => $dir);
        $conditions[] = $start;

        $arr = array('expiration' => $expiration, 'conditions' => $conditions);
        //echo json_encode($arr);
        //return;
        $policy = json_encode($arr);
        $base64_policy = base64_encode($policy);
        $string_to_sign = $base64_policy;
        $signature = base64_encode(hash_hmac('sha1', $string_to_sign, $key, true));

        $response = array();
        $response['accessid'] = $id;
        $response['host'] = $host;
        $response['policy'] = $base64_policy;
        $response['signature'] = $signature;
        $response['expire'] = $end;
        $response['callback'] = $base64_callback_body;
        //这个参数是设置用户上传指定的前缀
        $response['dir'] = $dir;
        echo json_encode($response);
        exit;
    }

    public function callback()
    {
        // 1.获取OSS的签名header和公钥url header
        $authorizationBase64 = "";
        $pubKeyUrlBase64 = "";
        /*
         * 注意：如果要使用HTTP_AUTHORIZATION头，你需要先在apache或者nginx中设置rewrite，以apache为例，修改
         * 配置文件/etc/httpd/conf/httpd.conf(以你的apache安装路径为准)，在DirectoryIndex index.php这行下面增加以下两行
            RewriteEngine On
            RewriteRule .* - [env=HTTP_AUTHORIZATION:%{HTTP:Authorization},last]
         **/
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $authorizationBase64 = $_SERVER['HTTP_AUTHORIZATION'];
        }
        if (isset($_SERVER['HTTP_X_OSS_PUB_KEY_URL'])) {
            $pubKeyUrlBase64 = $_SERVER['HTTP_X_OSS_PUB_KEY_URL'];
        }

        if ($authorizationBase64 == '' || $pubKeyUrlBase64 == '') {
            header("http/1.1 403 Forbidden");
            exit();
        }

        // 2.获取OSS的签名
        $authorization = base64_decode($authorizationBase64);
        // 3.获取公钥
        $pubKeyUrl = base64_decode($pubKeyUrlBase64);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $pubKeyUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        $pubKey = curl_exec($ch);
        if ($pubKey == "") {
            header("http/1.1 403 Forbidden");
            exit();
        }
        //4.获取回调body
        $body = file_get_contents('php://input');
        //5.拼接待签名字符串
        $authStr = '';
        $path = $_SERVER['REQUEST_URI'];
        $pos = strpos($path, '?');
        if ($pos === false) {
            $authStr = urldecode($path) . "\n" . $body;
        } else {
            $authStr = urldecode(substr($path, 0, $pos)) . substr($path, $pos, strlen($path) - $pos) . "\n" . $body;
        }
        // 6.验证签名
        $ok = openssl_verify($authStr, $authorization, $pubKey, OPENSSL_ALGO_MD5);
        if ($ok == 1) {
            header("Content-Type: application/json");
            $data = array("Status" => "Ok");
            $data = json_encode($data);
            //逻辑处理
            //$filename = input("filename", "null");
            $bodyParsed = $this->pasterString($body);
            $this->FILE_NAME = !empty($bodyParsed["filename"]) ? $bodyParsed["filename"] : "";
            $message = "callback success: " . $this->FILE_NAME . " " . date("Y-m-d H:i:s") . "\n";
            $message .= $data . "\n";
            $message .= $body . "\n";
            $message .= $path . "\n";
            error_log($message, 3, "/data/htdocs/kxt_adi/runtime/callback.log");
            $this->convert();
            echo $data;
            exit;
        } else {
            //header("http/1.1 403 Forbidden");
            $data = array("Status" => "fail");
            $data = json_encode($data);
            $message = "callback fail: " . date("Y-m-d H:i:s") . "\r\n";
            $message .= $data . "\n";
            error_log($message, 3, "/data/htdocs/kxt_adi/runtime/callback.log");
            echo $data;
            exit;
        }
    }

    private function convert()
    {
        $profile = DefaultProfile::getProfile('cn-hangzhou', $this->OSS_KEYID, $this->OSS_SECRET);
        //$profile = DefaultProfile::getProfile('cn-hangzhou', "NanqclFysEsHhJjd", "KoEM0jNsRjvoh81nSkQ7Je8l5jbeEE");
        $client = new DefaultAcsClient($profile);
        //$ret = $this->search_media_workflow($client, 'cn-hangzhou');
        try {
            $ret = $this->SubmitJobs($client);
        } catch (Exception $e) {
            //die($e->getMessage());
        }
    }

    public function notify()
    {
        //$xml = $GLOBALS["HTTP_RAW_POST_DATA"];
        //$xml = $HTTP_RAW_POST_DATA;
        $json = file_get_contents('php://input');
        error_log($json, 3, "/data/htdocs/kxt_adi/runtime/notify_xml.log");
        $message = "nofity success: " . date("Y-m-d H:i:s");
        error_log($message, 3, "/data/htdocs/kxt_adi/runtime/notify.log");
        http_response_code(204);
    }

    public function multiUploadFile()
    {
        //$object = "test/multipart-test.txt";
        $object = "14.mp4";
        $file = dirname(__FILE__) . "/13.mp4";
        try {
            $ossClient = new OssClient($this->OSS_KEYID, $this->OSS_SECRET, $this->OSS_ENDPOINT, false);
            $ossClient->multiuploadFile($this->OSS_BUCKET, $object, $file, []);
        } catch (OssException $e) {
            printf(__FUNCTION__ . ": FAILED\n");
            printf($e->getMessage() . "\n");
            return;
        }
        print(__FUNCTION__ . ":  OK" . "\n");
    }

    private function gmt_iso8601($time)
    {
        $dtStr = date("c", $time);
        $mydatetime = new \DateTime($dtStr);
        $expiration = $mydatetime->format(\DateTime::ISO8601);
        $pos = strpos($expiration, '+');
        $expiration = substr($expiration, 0, $pos);
        return $expiration . "Z";
    }

    private function SubmitJobs($c)
    {
        $input = '{
                    "Bucket" : "convert-test", 
                    "Location" : "oss-cn-hangzhou",
                    "Object" : ' . "\"$this->FILE_NAME\"" . ',
                 }';

        /*$outputs = '[{
                    "OutputObject" : "output.mp4",
                    "TemplateId" : "S00000001-200010",
                    "WaterMarks" : [{
                        "InputFile" : {
                            "Bucket" : "ali-hangzhou",
                            "Location" ; "oss-cn-hangzhou",
                            "Object" : "logo.png"
                            },
                        "WaterMarkTemplatedId" : "c17afc8efac14282a6c7e91ed96896dd"
                        }],
                        "MergeList" : [
                            {
                                "MergeURL" : "http://ali-hangzhou.oss-cn-hangzhou.aliyuncs.com/2.mp4",
                                "Start" : "15",
                                "Duration" : "5"
                            },
                            {
                                "MergeURL" : "http://ali-hangzhou.oss-cn-hangzhou.aliyuncs.com/1234.flv",
                                "Start" : "14",
                                "Duration" : "5"
                             }
                        ]
                  }]';*/
        $outputs = '[{
                    "OutputObject" : "output2.mp4", 
                    "TemplateId" : "S00000001-200030",
                  }]';
        $outputbucket = "convert-test";
        //$pipelineid = "097b8c1cae9c4af0a25bd28630e305e7";
        $pipelineid = "e50da60ee62546dd8ec9066ae5df2689";
        $req = new Mts\SubmitJobsRequest();
        $req->setInput($input);
        $req->setOutputBucket($outputbucket);
        $req->setOutputs($outputs);
        $req->setPipelineId($pipelineid);
        try {
            $resp = $c->doAction($req);
            if (!isset($resp->Code)) {
                //echo "success";
                //var_dump($resp);
                exit;
            } else {
                $code = $resp->Code;
                $message = $resp->Message;
                //var_dump($code);
                //var_dump($message);
                //echo "fail";
                exit;
            }
        } catch (Exception $e) {
            //todo:handle exception
        }
    }

    /*public function search_media_workflow($client, $regionId)
    {
        $request = new Mts\SearchMediaWorkflowRequest();
        $request->setAcceptFormat('JSON');
        $request->setRegionId($regionId); //重要
        $response = $client->getAcsResponse($request);
        return $response;
    }*/

    private function pasterString($string)
    {
        $arr = [];
        if (!empty($string)) {
            parse_str(urldecode($string), $arr);
            foreach ($arr as $k => $v) {
                $arr[$k] = trim($v, '"');
            }
        }
        return $arr;
    }

}