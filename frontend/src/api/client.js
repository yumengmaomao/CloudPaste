/**
 * API请求客户端
 * 提供统一的请求方法和错误处理
 */

import { getFullApiUrl } from "./config";
import { ApiStatus } from "./ApiStatus"; // 导入API状态码常量

/**
 * 添加认证令牌到请求头
 * @param {Object} headers - 原始请求头
 * @returns {Object} 添加了令牌的请求头
 */
function addAuthToken(headers) {
  // 如果请求头中已有Authorization，优先使用传入的值
  if (headers.Authorization) {
    console.log("使用传入的Authorization头:", headers.Authorization);
    return headers;
  }

  // 尝试从localStorage获取并添加
  const token = localStorage.getItem("admin_token");
  if (token) {
    console.log("从localStorage获取admin_token，长度:", token.length);
    return {
      ...headers,
      Authorization: `Bearer ${token}`,
    };
  }
  // 检查API密钥
  const apiKey = localStorage.getItem("api_key");
  if (apiKey) {
    console.log("从localStorage获取API密钥，长度:", apiKey.length);
    return {
      ...headers,
      Authorization: `ApiKey ${apiKey}`,
    };
  }

  console.log("未找到认证凭据，请求将不包含Authorization头");
  return headers;
}

/**
 * 通用API请求方法
 * @param {string} endpoint - API端点路径
 * @param {Object} options - 请求选项
 * @returns {Promise<any>} 请求响应数据
 */
export async function fetchApi(endpoint, options = {}) {
  const url = getFullApiUrl(endpoint);

  // 详细的调试日志
  const debugInfo = {
    url,
    method: options.method || "GET",
    headers: { ...(options.headers || {}) },
    body: options.body,
    timestamp: new Date().toISOString(),
  };

  console.log(`🚀 API请求: ${debugInfo.method} ${debugInfo.url}`, debugInfo);

  // 默认请求选项
  const defaultOptions = {
    headers: {
      "Content-Type": "application/json",
    },
    // 不再使用credentials: 'include'，因为我们使用Bearer token认证
  };

  // 合并默认选项和用户传入的选项，并添加认证令牌
  const requestOptions = {
    ...defaultOptions,
    ...options,
    headers: addAuthToken({
      ...defaultOptions.headers,
      ...options.headers,
    }),
  };

  // 如果请求体是对象类型，则自动序列化为JSON
  if (requestOptions.body && typeof requestOptions.body === "object") {
    requestOptions.body = JSON.stringify(requestOptions.body);
  }

  try {
    const startTime = Date.now();
    const response = await fetch(url, requestOptions);
    const endTime = Date.now();
    const timeTaken = endTime - startTime;

    console.log(`⏱️ API响应耗时: ${timeTaken}ms, 状态: ${response.status}`, {
      url,
      status: response.status,
      statusText: response.statusText,
      headers: Object.fromEntries([...response.headers.entries()]),
    });

    // 首先解析响应内容
    let responseData;
    const contentType = response.headers.get("content-type");
    if (contentType && contentType.includes("application/json")) {
      responseData = await response.json();
      console.log(`📦 API响应数据(${url}):`, responseData);
    } else {
      responseData = await response.text();
      console.log(`📝 API响应文本(${url}): ${responseData.substring(0, 100)}${responseData.length > 100 ? "..." : ""}`);
    }

    // 如果响应不成功，抛出错误
    if (!response.ok) {
      // 特殊处理401未授权错误
      if (response.status === ApiStatus.UNAUTHORIZED) {
        console.error(`🚫 授权失败(${url}):`, responseData);

        // 判断是否是密码验证请求（文本或文件分享的密码验证）
        const isTextPasswordVerify = endpoint.match(/^(\/)?paste\/[a-zA-Z0-9_-]+$/i) && options.method === "POST";
        const isFilePasswordVerify = endpoint.match(/^(\/)?public\/files\/[a-zA-Z0-9_-]+\/verify$/i) && options.method === "POST";
        const hasPasswordInBody = options.body && (typeof options.body === "string" ? options.body.includes("password") : options.body.password);

        // 检查是否是修改密码请求
        const isChangePasswordRequest = endpoint.includes("/admin/change-password") && options.method === "POST";

        const isPasswordVerify = (isTextPasswordVerify || isFilePasswordVerify) && hasPasswordInBody;

        // 如果是密码验证请求，直接返回错误，不清除令牌
        if (isPasswordVerify) {
          console.log(`密码验证失败，不清除认证令牌。端点: ${endpoint}`);

          // 确保返回后端提供的具体错误信息
          const errorMessage = responseData && responseData.message ? responseData.message : "密码错误";

          throw new Error(errorMessage);
        }

        // 如果是修改密码请求，可能是当前密码验证失败
        if (isChangePasswordRequest) {
          // 返回具体的错误信息，通常是"当前密码错误"
          const errorMessage = responseData && responseData.message ? responseData.message : "验证失败";

          throw new Error(errorMessage);
        }

        // 判断使用的是哪种认证方式
        const authHeader = requestOptions.headers.Authorization || "";

        // 管理员令牌过期，清除令牌并触发事件
        if (authHeader.startsWith("Bearer ")) {
          localStorage.removeItem("admin_token");
          window.dispatchEvent(new CustomEvent("admin-token-expired"));
          throw new Error("管理员会话已过期，请重新登录");
        }
        // API密钥处理
        else if (authHeader.startsWith("ApiKey ")) {
          // 仅当API密钥确实无效（而不是权限问题）时才清除密钥
          // 检查是否是文件访问权限问题（文件相关API）
          const isFileAccess = url.includes("/api/files") || url.includes("/api/upload");
          const isPermissionIssue = responseData && responseData.message && (responseData.message.includes("未授权访问") || responseData.message.includes("无权访问"));

          if (isFileAccess && isPermissionIssue) {
            // 仅抛出错误，但不清除API密钥
            throw new Error(responseData.message || "访问被拒绝，您可能无权执行此操作");
          } else {
            // 其他情况（如密钥真的无效）时，清除密钥
            localStorage.removeItem("api_key");
            localStorage.removeItem("api_key_permissions");
            window.dispatchEvent(new CustomEvent("api-key-invalid"));
            throw new Error("API密钥无效或已过期");
          }
        } else {
          throw new Error("未授权访问，请登录后重试");
        }
      }

      // 对409状态码做特殊处理（链接后缀冲突或其他冲突）
      if (response.status === ApiStatus.CONFLICT) {
        console.error(`❌ 资源冲突错误(${url}):`, responseData);
        // 使用后端返回的具体错误信息，无论是字符串形式还是对象形式
        if (typeof responseData === "string") {
          throw new Error(responseData);
        } else if (responseData && typeof responseData === "object" && responseData.message) {
          throw new Error(responseData.message);
        } else {
          throw new Error("链接后缀已被占用，请尝试其他后缀");
        }
      }

      // 处理新的后端错误格式 (code, message)
      if (responseData && typeof responseData === "object") {
        console.error(`❌ API错误(${url}):`, responseData);
        throw new Error(responseData.message || `HTTP错误 ${response.status}: ${response.statusText}`);
      }

      console.error(`❌ HTTP错误(${url}): ${response.status}`, responseData);
      throw new Error(`HTTP错误 ${response.status}: ${response.statusText}`);
    }

    // 处理新的后端统一响应格式 (code, message, data)
    if (responseData && typeof responseData === "object") {
      // 如果响应包含code字段
      if ("code" in responseData) {
        // 成功响应，code应该是200或201(创建成功)
        if (responseData.code !== ApiStatus.SUCCESS && responseData.code !== ApiStatus.CREATED) {
          console.error(`❌ API业务错误(${url}):`, responseData);
          throw new Error(responseData.message || "请求失败");
        }

        // 如果成功，返回完整的responseData
        return responseData;
      }

      // 如果响应不包含code字段，直接返回整个响应
      return responseData;
    }

    // 如果响应不符合统一格式，则直接返回
    return responseData;
  } catch (error) {
    console.error(`❌ API请求失败(${url}):`, error);
    throw error;
  }
}

/**
 * GET请求方法
 */
export function get(endpoint, options = {}) {
  return fetchApi(endpoint, { ...options, method: "GET" });
}

/**
 * POST请求方法
 */
export function post(endpoint, data, options = {}) {
  return fetchApi(endpoint, { ...options, method: "POST", body: data });
}

/**
 * PUT请求方法
 */
export function put(endpoint, data, options = {}) {
  return fetchApi(endpoint, { ...options, method: "PUT", body: data });
}

/**
 * DELETE请求方法
 */
export function del(endpoint, data, options = {}) {
  return fetchApi(endpoint, { ...options, method: "DELETE", body: data });
}

/**
 * 请求拦截器 - 目前为简化版，可扩展为更复杂的实现
 */
export function setupInterceptors(handlers = {}) {
  // 在这里可以实现全局请求/响应拦截器
  // 例如：添加认证令牌、刷新令牌逻辑等

  const { onRequest, onResponse, onError } = handlers;

  // 这里提供一个简单的拦截器框架，可根据需要扩展
  return {
    request: (config) => {
      if (onRequest) {
        return onRequest(config);
      }
      return config;
    },
    response: (response) => {
      if (onResponse) {
        return onResponse(response);
      }
      return response;
    },
    error: (error) => {
      if (onError) {
        return onError(error);
      }
      throw error;
    },
  };
}
