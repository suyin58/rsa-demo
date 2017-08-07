package com.wjs.rsaDemo;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

public class RsaDemo {

	/**
	 * 加签用公钥
	 */
	public static String signPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3GFaW5S8GI7ejxhnVjhC6is3k5ZXY+eHK7hV42W7aSPuQ1dg72XZ2D/cLIdv4wNf8H3vf0e2O0YNwuwst6rD/BWey0yBUnToTm6xsJg5dCMYNQCocgtDrBTgHYSkZY/eno0MMn1KdRN0ILvAvz4BmENOkfuD3TEHgzXZS+prDZOKIHfW0HUYNEGk3LQC6VKQawKY+QO7k188wokV85FzmYFvjkkOE0UHuFL/p2zGnwVv+ZHq34TzZQaQNnO3/INQqxi+HiPfpD2oTJDY1+cAqukCD46hM+4qPx4t6A1fe+Tr8GE4DeGW3+MIqcuCs79cGj1Xtca8AoGCqK/Nx2Y0JwIDAQAB";

	/**
	 * 加签用私钥
	 */
	public static String signPrivateKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDcYVpblLwYjt6PGGdWOELqKzeTlldj54cruFXjZbtpI+5DV2DvZdnYP9wsh2/jA1/wfe9/R7Y7Rg3C7Cy3qsP8FZ7LTIFSdOhObrGwmDl0Ixg1AKhyC0OsFOAdhKRlj96ejQwyfUp1E3Qgu8C/PgGYQ06R+4PdMQeDNdlL6msNk4ogd9bQdRg0QaTctALpUpBrApj5A7uTXzzCiRXzkXOZgW+OSQ4TRQe4Uv+nbMafBW/5kerfhPNlBpA2c7f8g1CrGL4eI9+kPahMkNjX5wCq6QIPjqEz7io/Hi3oDV975OvwYTgN4Zbf4wipy4Kzv1waPVe1xrwCgYKor83HZjQnAgMBAAECggEAJWZYIUaijUBhwMMRdm5h3L+s1N0kw42dQOwtl0PChFtWqhMAHmCYkbx0rxHlCQ+fjn6w0FbpNDH1T+koxZqzW+qHYlT/dXDlo7nhaejLh0wVZZlQ/NmwiFmalyfVhm7eBuZE9aSRqEC+6ncyhMIPHzn88YVPoZAaiEfxMpL7y/e3UAXfnzMFXqVi2ihMbtu6w1FUMgnWjy8WqqwgoTFVdR6GjWUROAtfTUwZe6Fw+KVm2+KKgMWPPE2SPxXp3q0T6AwI6Eg1RbIjUYUsl/9DkUdXJBt9G6eaNbY7WkeRrN8HKMCA1zOIv2sJWEnHkg2N6FgTHkSWIBXjiJ5vsphXUQKBgQDvcd0+J0PT1qAphgg3xTjQBim7MOsFG2VvQH0r72Fj4qy2BOsRyuotBJBQlgyq/csyduHew/068qWCCQb534dTvVtOXXQ1rSvyIM/UjFM0/5BExtKluz1zm2tQt0KDEOyZ1OnbGryuV8Ap8ftAfy1XkiVeqo1E9T6ej1kRzopABQKBgQDrngzRKsQPKDaCHb7Wn4QxYq5u8bYXn/EymynOjJcGxeJ/KotFCcemWFlWjIsi/k0sCJ3yWATARqCd7eSYcW/AmNpe2b/g4w699WvlSWq+E5hCA/GVwQpwRJSYN/PhDqdkBRngJ/AD8lf6CEGxG3SaMYCfXCkdFYwYYgdRGfUXOwKBgA3ERiwkpcmwNVUt15sdQ77yG8Qfc+O/R321/3xfLwJHLhbpAXrsZ7pe4M1BU0khfmVQYHwmWJDjEpD/Y99J8sXlxTIkPWI4qqYpLMnTp5UMfIb3x3Sv50CWVv01DCXs+y19CFUInICJmwrOVtvGdBzs0ik3NRgZ4ZfMNhrH/TrhAoGAB55BndW7Jx5OvOBHVlssBAjDyRSJpbPnMZKwxFvpWi+1xhTTEfVh/i/nG5RJv2Tni9/vc3GDHdBqyxBxDrjEOz71+JEj0hqlVGEGDxDTobeyeZf1DLmEI+MjxtQwT3uQz/wWPRgte4MvcwcnUJmpqH6nQP/S2Hzk3bj1sZqcQRcCgYBG4JCI7b1qJnvOPyP4Eqt6GcZ3OpbwkwKkiYQ2lwgn+wHT/7l3HfpTpBKZFMSknrbD11MzE2Q6niP6luG+HZPBsLyEQduipqaFe/GLmTGjljnj2wG3981sQluyrNlNPbDrTQKQERkcy6v8L6NHnIsYrUT/uHC6UJTqVYWjk1WVeQ==";

	/**
	 * 加密用私钥
	 */
	private static String encryptPrivateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCd4FMhHvZGRBAMuRqn0ZmvvNFBkYyGsf9NOaS+CMAgHB4ib+ciDE3lCfYZHhi0vV2iMMBIanwaNev4c0uu4WyeFLQkMAUbgW/iIo+pR8xocjo9RPsTxN0IOL4KpSeTLM2MQZKnyffBugoIt15mZzzij6lcXy2CI/2wcNKg4Nw6v1iZ8Et+wEgqlPVeASaTAFSjmJNQn4aIy8Fpzll8ADP9neUQCMOWG87lDbU9RCs0YqAFfo61MyYj+KbIvhWwyycZJIrKFwKsEn4tViB5UFegRP4DgSjEzq/glvnwgVNBDiYFOKZ8lqkS+bfhHBA+w+X+fJ2CTalKm3+NZTHYeX5DAgMBAAECggEAf9p1N/NtGkZwgP0+2v1havKMvH70wPhReubdxZAsl1RuCxF4qxgv1PaWOI0pEOXyeDDm5z5lNozIhrJIbl3cqsC1ikDhQf827nlywnKE1Wj8RTYh50acgdYCAXjybbvw0k8gR4XGgTr6eUiWyHN+2TPiwg3KOwSOpF8aFHNFpsSbwrOg7xlzNov6M28B/godUpGgPv0PuN7M6DMOi18QiwWSPa1ycnBt7tWZkyEl/vMdAV0be2RfY93Lvzgp8a/mI+A/c8hcBJj5vJDwJR3CnqKR5RceOPrA4eT2zXJOcR43DfWPo7Q+7Buii1ERoSF3Um4t5JpSr/2j2xHdJGmRMQKBgQDfODepUuiKMW5IPVdkdF62oDmF/CLkizbDsAPXeG6tWPZUYX7cHkoEuPY0LxACIcM3ZnZyCUBtIDMk7bLEIw3wuXqh+1hVQrS5VCosbVq6LxcT5MMQouMxRtHSScdIcsGUYZSIVjlXuQdDXzrKhg3LSTLdWdYAb4pIygHb0UbsxwKBgQC1D5Izs3UGFXpySMdeDo8eF4TkmQqGlYI1rEkZxHNcSH9BGTJH3EmuAb5/8UxSDWX7GPpLJeexSVHrfADYl4CmYpDITpihhaB+t68b9yHY7EwO/gF2QcTvvwIIfWJmjPyCJTwT6wRtmv5WQnt7tt0ObZq0tovJVdn8cbpyVLAOpQKBgQCaTWs0siorNSZN65FY0JSUW8fH1dZs88sElMzjCs4/KCsHg2nFUW7LOux+gDXps1sWFc803y5ZARQ5p9KWgMDnMeASzwNt1LHHFuYcVe+MmnayesVY37B7ZMAwRG3sp98m6hlZ8XisKixaJx8l1mr8pnnxx2MGZBRMYs/MGyuTCwKBgALxOtX+P5OWu8OprRu5Ltg1V6KDXilruo72usVhbOJ+BxtetnN2f/gE7TyVBkF7GEIpWL/p4Mb/wwYJoNXkOGH7zhCDPnW5fy8v+veAX5tv05iWxh1O2k1vFDBhIT07Y0sWIdDNC+hgEWwDbpBHG3aFj3MKWGEwNPemPXpoJ+hFAoGBAJioGALh7yp4bpHTdwrGtSWm8TdXBx8nC8rFNI9SUtSopafN2eHLwZ6PnVvN6kgCIlQ7HbxQruuGKiKd9UDTbEbFIaidUAoyzZm7/cYc0YJRVXnQNLiiz758VHtx1YEdscMXj10X4NSK8sRMjeWQhT1v5PaNafG65oSkuyFrIlPk";

	/**
	 * 加密用公钥
	 */
	public static String encryptPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAneBTIR72RkQQDLkap9GZr7zRQZGMhrH/TTmkvgjAIBweIm/nIgxN5Qn2GR4YtL1dojDASGp8GjXr+HNLruFsnhS0JDAFG4Fv4iKPqUfMaHI6PUT7E8TdCDi+CqUnkyzNjEGSp8n3wboKCLdeZmc84o+pXF8tgiP9sHDSoODcOr9YmfBLfsBIKpT1XgEmkwBUo5iTUJ+GiMvBac5ZfAAz/Z3lEAjDlhvO5Q21PUQrNGKgBX6OtTMmI/imyL4VsMsnGSSKyhcCrBJ+LVYgeVBXoET+A4EoxM6v4Jb58IFTQQ4mBTimfJapEvm34RwQPsPl/nydgk2pSpt/jWUx2Hl+QwIDAQAB";

	public static void main(String[] args) {

		// 组装数据
		encode("加签数据");

		// 解签
		System.out.println("解签后数据---->" + decode());

	}

	// 参数容器
	static Map<String, String> paramMap = new HashMap<String, String>();

	private static String charset = "utf-8";

	public static void encode(String bizParam) {
		try {

			// 使用网金社公钥对业务参数进行加密
			String bizParamEncrypt = HashUtil
					.encryptBASE64(RSAUtil.encryptByPublicKey(bizParam.getBytes(charset), encryptPublicKey));
			paramMap.put("bizParams", URLEncoder.encode(bizParamEncrypt, charset));

			// 计算并组装签名
			String sign = RSAUtil.sign(bizParam.getBytes(charset), signPrivateKey);
			paramMap.put("sign", URLEncoder.encode(sign, charset));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static String decode() {

		// 解密参数
		String bizParams = paramMap.get("bizParams");
		try {
			bizParams = URLDecoder.decode(bizParams, charset);
		} catch (UnsupportedEncodingException e1) {
			e1.printStackTrace();
		}
		String bizParamsJson = null;
		try {
			bizParamsJson = new String(
					RSAUtil.decryptByPrivateKey(HashUtil.decryptBASE64(bizParams), encryptPrivateKey));
		} catch (Exception e) {
			e.printStackTrace();
		}

		// 验签
		checkSign(bizParamsJson, signPublicKey, paramMap.get("sign"));

		return bizParamsJson;
	}

	private static void checkSign(String data, String publicKey, String sign) {
		boolean verify = false;
		try {
			sign = URLDecoder.decode(sign, charset);
		} catch (UnsupportedEncodingException e1) {
			e1.printStackTrace();
		}
		try {
			verify = RSAUtil.verify(data.getBytes(charset), publicKey, sign);
		} catch (Exception e) {
			e.getMessage();
		}
		if (!verify) {
			System.err.println("验签失败");
		} else {
			System.out.println("验签成功");
		}

	}

}
