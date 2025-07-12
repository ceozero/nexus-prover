package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"nexus-prover/internal/utils"
	"nexus-prover/pkg/types"
	pb "nexus-prover/proto"

	"google.golang.org/protobuf/proto"
)

// Client API客户端
type Client struct {
	httpClient *http.Client
	tasksURL   string
	submitURL  string
}

// NewClient 创建新的API客户端
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second, // 30秒超时
			Transport: &http.Transport{
				MaxIdleConns:        100,              // 最大空闲连接数
				MaxIdleConnsPerHost: 10,               // 每个主机的最大空闲连接数
				IdleConnTimeout:     90 * time.Second, // 空闲连接超时时间
				TLSHandshakeTimeout: 10 * time.Second, // TLS握手超时时间
			},
		},
		tasksURL:  "http://192.168.1.118:8080/v3/tasks",
		submitURL: "http://192.168.1.118:8080/v3/tasks/submit",
	}
}

// GetExistingTasks 获取已分配任务（优先）
func (c *Client) GetExistingTasks(nodeID string) ([]*pb.GetProofTaskResponse, error) {
	// 构造 protobuf body
	req := &pb.GetTasksRequest{
		NodeId:     nodeID,
		NextCursor: "",
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}

	// 构造 GET 请求，body 为 protobuf
	httpReq, err := http.NewRequest("GET", c.tasksURL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limit exceeded: %s", string(respData))
	}

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("no existing tasks found")
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("get existing tasks failed: %s", string(respData))
	}

	// 解析响应
	var tasksResp pb.GetTasksResponse
	if err := proto.Unmarshal(respData, &tasksResp); err != nil {
		return nil, err
	}

	if len(tasksResp.Tasks) == 0 {
		return nil, fmt.Errorf("no existing tasks found")
	}

	// 转换为GetProofTaskResponse格式
	var tasks []*pb.GetProofTaskResponse
	for _, task := range tasksResp.Tasks {
		tasks = append(tasks, &pb.GetProofTaskResponse{
			TaskId:       task.TaskId,
			ProgramId:    task.ProgramId,
			PublicInputs: task.PublicInputs,
		})
	}

	return tasks, nil
}

// GetNewTask 获取新任务
func (c *Client) GetNewTask(nodeID string, pub ed25519.PublicKey) (*pb.GetProofTaskResponse, error) {
	req := &pb.GetProofTaskRequest{
		NodeId:           nodeID,
		NodeType:         pb.NodeType_CLI_PROVER,
		Ed25519PublicKey: []byte(pub),
	}

	data, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(c.tasksURL, "application/octet-stream", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limit exceeded: %s", string(respData))
	}

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("no task available")
	}

	// if resp.StatusCode != 200 {
	// 	return nil, fmt.Errorf("get new task failed: %s", string(respData))
	// }

	var proofResp pb.GetProofTaskResponse
	if err := proto.Unmarshal(respData, &proofResp); err != nil {
		return nil, err
	}

	return &proofResp, nil
}

// FetchTaskBatch 批量获取新任务
func (c *Client) FetchTaskBatch(nodeID string, pub ed25519.PublicKey, batchSize int, state *types.TaskFetchState) ([]*pb.GetProofTaskResponse, error) {
	var tasks []*pb.GetProofTaskResponse
	var rateLimitHit bool
	var consecutive404Hit bool

	// 批量获取新任务
	for i := 0; i < batchSize; i++ {
		task, err := c.GetNewTask(nodeID, pub)
		if err != nil {
			if strings.Contains(err.Error(), "rate limit exceeded") {
				rateLimitHit = true
				break
			}
			if strings.Contains(err.Error(), "no task available") {
				state.Consecutive404s++
				if state.Consecutive404s >= 5 {
					consecutive404Hit = true
					break
				}
				continue
			}
			return nil, err
		}

		// 成功获取任务
		tasks = append(tasks, task)
		state.Consecutive404s = 0 // 重置404计数器
	}

	// 记录批量获取结果
	if len(tasks) > 0 {
		utils.LogWithTime("[batch@%s] 📥 批量获取成功: %d/%d 个任务", nodeID, len(tasks), batchSize)
	} else if rateLimitHit {
		utils.LogWithTime("[batch@%s] ⏳ 批量获取被限流中断", nodeID)
	} else if consecutive404Hit {
		utils.LogWithTime("[batch@%s] 💤 批量获取因连续404中断 (连续%d次)", nodeID, state.Consecutive404s)
	} else {
		utils.LogWithTime("[batch@%s] 💤 批量获取无任务可用", nodeID)
	}

	return tasks, nil
}

// SubmitProof 提交证明（protobuf POST）
func (c *Client) SubmitProof(task *types.Task, proof []byte, priv ed25519.PrivateKey) error {
	// 计算证明哈希
	proofHash := fmt.Sprintf("%x", sha256.Sum256(proof))

	// 构造签名数据: task_id + proof_hash
	signData := []byte(task.TaskID + proofHash)

	// 使用私钥签名
	signature := ed25519.Sign(priv, signData)

	// 构造完整的 SubmitProofRequest
	req := &pb.SubmitProofRequest{
		TaskId:           task.TaskID,
		NodeType:         pb.NodeType_CLI_PROVER,
		ProofHash:        proofHash,
		Proof:            proof,
		Ed25519PublicKey: priv.Public().(ed25519.PublicKey),
		Signature:        signature,
		// 添加节点遥测数据（可选）
		NodeTelemetry: &pb.NodeTelemetry{
			Location: &[]string{"unknown"}[0],
		},
	}

	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(c.submitURL, "application/octet-stream", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respData, _ := ioutil.ReadAll(resp.Body)

	// 接受200 OK和204 No Content作为成功状态
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("submitProof failed: httpCode:%d, response:%s", resp.StatusCode, string(respData))
	}

	return nil
}
