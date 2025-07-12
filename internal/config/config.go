package config

import (
	"encoding/json"
	"io/ioutil"
)

// Config 配置结构体
type Config struct {
	NodeIDs               []string `json:"node_ids"` // 节点ID数组
	UserID                string   `json:"user_id"`
	WalletAddress         string   `json:"wallet_address"`
	RequestDelay          int      `json:"request_delay"`             // 请求间隔（秒）
	ProverWorkers         int      `json:"prover_workers"`            // 证明计算worker数量
	TaskQueueCapacity     int      `json:"task_queue_capacity"`       // 任务队列容量
	BatchSize             int      `json:"batch_size"`                // 每次获取任务的批量大小
	Max404sBeforeGivingUp int      `json:"max_404s_before_giving_up"` // 404容忍次数
	TaskFetchInterval     int      `json:"task_fetch_interval"`       // 任务获取间隔（秒）
	QueueLogInterval      int      `json:"queue_log_interval"`        // 队列日志打印间隔（秒）
}

// 常量定义
const (
	// 批处理配置
	BATCH_SIZE                = 5  // 每次获取5个任务 (增加批量大小)
	MAX_404S_BEFORE_GIVING_UP = 3  // 减少404容忍次数，更快发现问题
	TASK_FETCH_INTERVAL       = 1  // 1秒间隔获取任务
	QUEUE_LOG_INTERVAL        = 30 // 30秒打印日志时间间隔

	// 任务API地址
	// TASKS_API_URL    = "https://beta.orchestrator.nexus.xyz/v3/tasks"
	// TASKS_SUBMIT_URL = "https://beta.orchestrator.nexus.xyz/v3/tasks/submit"
	TASKS_API_URL    = "http://192.168.1.118:8080/v3/tasks"
	TASKS_SUBMIT_URL = "http://192.168.1.118:8080/v3/tasks/submit"

	// 队列配置 - 默认值，可通过配置文件覆盖
	DEFAULT_TASK_QUEUE_CAPACITY = 110 // 默认任务队列容量
)

// LoadConfig 加载配置文件
func LoadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// 设置默认值 - JSON配置优先，未配置时使用默认值
	if cfg.TaskQueueCapacity <= 0 {
		cfg.TaskQueueCapacity = DEFAULT_TASK_QUEUE_CAPACITY
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = BATCH_SIZE
	}
	if cfg.Max404sBeforeGivingUp <= 0 {
		cfg.Max404sBeforeGivingUp = MAX_404S_BEFORE_GIVING_UP
	}
	if cfg.TaskFetchInterval <= 0 {
		cfg.TaskFetchInterval = TASK_FETCH_INTERVAL
	}
	if cfg.QueueLogInterval <= 0 {
		cfg.QueueLogInterval = QUEUE_LOG_INTERVAL
	}

	return &cfg, nil
}
