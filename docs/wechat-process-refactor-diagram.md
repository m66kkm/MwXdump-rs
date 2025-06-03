# 微信进程检测重构方案架构图

## 当前架构问题

```mermaid
graph TD
    A[CLI Commands] --> B[detect_processes]
    A --> C[手动过滤 WeChat.exe]
    A --> D[手动版本验证]
    
    E[Key Module] --> F[进程名检查]
    E --> G[版本推断]
    
    B --> H[WindowsProcessDetector]
    H --> I[get_process_list_with_paths]
    I --> J[已过滤微信进程]
    
    style C fill:#ffcccc
    style D fill:#ffcccc
    style F fill:#ffcccc
    
    C -.->|重复逻辑| J
    D -.->|重复验证| G
    F -.->|多余检查| J
```

## 重构后架构

```mermaid
graph TD
    A[CLI Commands] --> B[get_valid_main_processes]
    E[Key Module] --> F[KeyVersion::from_process]
    
    B --> C[WindowsProcessDetector]
    C --> D[get_main_wechat_processes]
    C --> G[validate_process_version]
    C --> H[detect_processes]
    
    D --> I[过滤 WeChat.exe]
    G --> J[统一版本验证]
    H --> K[get_process_list_with_paths]
    K --> L[已过滤微信进程]
    
    B --> M[组合调用]
    M --> D
    M --> G
    
    style B fill:#ccffcc
    style G fill:#ccffcc
    style M fill:#ccffcc
```

## 重构前后对比

### 调用链简化

```mermaid
sequenceDiagram
    participant CLI as CLI Command
    participant Det as Detector
    participant Proc as Process List
    
    Note over CLI,Proc: 重构前 (复杂)
    CLI->>Det: detect_processes()
    Det->>Proc: get filtered processes
    Proc-->>Det: all wechat processes
    Det-->>CLI: all wechat processes
    CLI->>CLI: filter WeChat.exe manually
    CLI->>CLI: validate version manually
    CLI->>CLI: process valid processes
    
    Note over CLI,Proc: 重构后 (简化)
    CLI->>Det: get_valid_main_processes()
    Det->>Det: get_main_wechat_processes()
    Det->>Det: validate_process_version()
    Det-->>CLI: valid WeChat.exe processes
    CLI->>CLI: process valid processes
```

## 新增方法关系图

```mermaid
classDiagram
    class WindowsProcessDetector {
        -wechat_process_names: Vec~String~
        +detect_processes() Vec~ProcessInfo~
        +get_main_wechat_processes() Vec~ProcessInfo~
        +validate_process_version(process) bool
        +get_valid_main_processes() Vec~ProcessInfo~
        +get_all_wechat_processes() Vec~ProcessInfo~
    }
    
    class ProcessInfo {
        +pid: u32
        +name: String
        +path: PathBuf
        +version: WeChatVersion
        +data_dir: Option~PathBuf~
    }
    
    class WeChatVersion {
        <<enumeration>>
        V3x
        V4x
        Unknown
    }
    
    WindowsProcessDetector --> ProcessInfo : returns
    ProcessInfo --> WeChatVersion : contains
    
    note for WindowsProcessDetector : "新增的业务导向方法\n基于现有detect_processes()"
```

## 重构影响范围

```mermai
d
mindmap
  root((重构影响))
    Windows Process Detector
      添加新方法
        get_main_wechat_processes
        validate_process_version
        get_valid_main_processes
      保持兼容性
        detect_processes 不变
        现有接口保留
    CLI Commands
      简化逻辑
        移除手动过滤
        移除重复验证
      改进用户体验
        更清晰的错误信息
        更好的进度提示
    Key Module
      清理接口
        移除防御性检查
        专注版本推断
      提高可读性
        简化逻辑流程
        改进日志记录
```

## 代码行数变化预估

```mermaid
xychart-beta
    title "代码行数变化"
    x-axis [WindowsProcessDetector, CLI Commands, Key Module]
    y-axis "代码行数" 0 --> 200
    bar [+30, -26, -8]
```

## 重构时间线

```mermaid
gantt
    title 重构实施时间线
    dateFormat  YYYY-MM-DD
    section 第一阶段
    扩展WindowsProcessDetector    :a1, 2025-06-03, 2d
    添加单元测试                 :a2, after a1, 1d
    section 第二阶段  
    重构CLI Commands             :b1, after a2, 2d
    功能测试                     :b2, after b1, 1d
    section 第三阶段
    重构Key Module               :c1, after b2, 1d
    代码审查                     :c2, after c1, 1d
    section 第四阶段
    集成测试                     :d1, after c2, 1d
    性能验证                     :d2, after d1, 1d
```

## 风险评估矩阵

```mermaid
quadrantChart
    title 重构风险评估
    x-axis 低影响 --> 高影响
    y-axis 低概率 --> 高概率
    
    quadrant-1 监控区域
    quadrant-2 重点关注
    quadrant-3 可接受
    quadrant-4 需要缓解
    
    接口变更: [0.3, 0.2]
    逻辑依赖: [0.6, 0.3]
    性能退化: [0.4, 0.1]
    测试覆盖不足: [0.7, 0.4]
    向后兼容性: [0.2, 0.1]
```

## 成功指标仪表板

```mermaid
pie title 重构完成度指标
    "代码简化" : 30
    "功能验证" : 25
    "性能保持" : 20
    "测试覆盖" : 15
    "文档更新" : 10
```

---

这些图表展示了重构方案的各个方面：
- **架构对比**: 清晰显示重构前后的差异
- **调用链简化**: 展示API使用的简化过程  
- **影响范围**: 全面了解重构涉及的模块
- **时间规划**: 合理的实施时间线
- **风险管控**: 识别和评估潜在风险
- **成功衡量**: 明确的完成标准