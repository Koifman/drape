# DRAPE Index Implementation for CrowdStrike

## Overview

This query is an attempt to implement the **DRAPE Index** (Detection Reliability And Precision Efficiency) for CrowdStrike detections using Humio/LogScale Query Language.


### Score Interpretation

| DRAPE Score | Classification | Meaning |
|-------------|----------------|---------|
| < 0 | Bad | Noise-dominant, unreliable detection |
| 0-5 | Weak | Marginal value, needs improvement |
| 5-15 | Decent | Useful detection with acceptable precision |
| > 15 | Strong | High-value, precise, efficient detection |

### Formula

```
DRAPE = (w × TP × (TP / (TP + FP + 1))) - (k × FP)
```

Where:
- **TP**: True Positive count
- **FP**: False Positive count
- **w**: Weight parameter that boosts reward for precision (default: 2.0)
- **k**: Penalty parameter for false positives (default: 0.5)

The "zero line" occurs around a TP:FP ratio of 1:90, but can be tuned via the w/k parameters.

## Query Implementation - (With help from [MlgHodorMech](https://www.reddit.com/user/MlgHodorMech/))

```humio
(#event_simpleName="Event_UserActivityAuditEvent" OperationName="detection_update" Attributes.resolution=/(true|false)_positive/i) OR (#event_simpleName=/DetectionSummaryEvent/)
| CompoId:=coalesce(Attributes.composite_id, CompositeId)
| RuleName:=coalesce(DetectName, IOARuleName, Name) // Added in RuleName here since I wanted that in mine, plus can replace a few of items in the first groupBy()
| selfJoinFilter([CompoId], where=[{#event_simpleName="Event_UserActivityAuditEvent" OperationName="detection_update" Attributes.resolution=/(true|false)_positive/i}, {#event_simpleName=/DetectionSummaryEvent/}], prefilter=true)
| groupBy([CompoId], function=([collect([Attributes.resolution, UserId, UserIp, EventUUID, ComputerName, RuleName]), count(#event_simpleName, distinct=true, as=eventCount)])) // Updated groupBy for the RuleName
| case {
    Attributes.resolution="true_positive" | TP:=1 | FP:=0;
    Attributes.resolution="false_positive" | TP:=0 | FP:=1;
    * | TP:=0 | FP:=0;
  }
| TP:=coalesce(TP, 0) 
| FP:=coalesce(FP, 0)


| groupBy([RuleName], function=[sum(FP, as=FP), sum(TP, as=TP)]) // Further groupBy to pivot on the RuleName. The initial query had sum(TP), sum(FP), but this errored as the default field the sum function creates is _sum, and it was creating it for both. Adding in the names makes it work without the error. 


| w:=1.5 | k:=0.3 // my values for testing
| Total := FP+TP // create a total field - this allowed me to calculate percentage rates and make the score calculation a bit easier / cleaner


// Logarythmic calculations


// Relevant Python chunk:
// tlog = math.log10(tp+1.0)
// flog = math.log10(fp+1.0)


// Logscale calculations seem only to be able to be done on fields, not a value of a calculation. 
| tlog := TP + 1.0
| flog := FP + 1.0
| tlog := math:log10(tlog)
| flog := math:log10(flog)


// Score calculation


// Relevant Python chunk:
// score = (tlog * (1.0 + w * precision)) - ((k *  flog) / (tlog + 1.0))


| DRAPE := (tlog * (1.0 + w * (TP / Total))) - ((k * flog) / (tlog + 1.0))
| sort(DRAPE, order=desc)


// Rounding / formatting
// Relevant Python chunk:
// return round(score * 10.0,2)
| DRAPE := DRAPE * 10.0
| DRAPE := format("%.2f", field=DRAPE) // Round to two decimal places
| select([RuleName, FP, TP, Total, DRAPE]) // select just the values we want in the display
```

## How It Works

### 1. Event Collection
The query correlates two event types:
- **Event_UserActivityAuditEvent**: Analyst resolution actions (TP/FP labels)
- **DetectionSummaryEvent**: The actual detection/alert events

### 2. Correlation via Composite ID
Uses `selfJoinFilter` to efficiently join events sharing the same `composite_id`, which links detection events to their resolution status.

### 3. Resolution Classification
Extracts the resolution type from audit events:
- `true_positive`: Confirmed threat
- `false_positive`: Benign activity misclassified as threat

### 4. Aggregation by Detection
Groups events by composite ID and collects:
- Resolution status
- Analyst information (UserId, UserIp)
- Detection metadata (DetectName, IOARuleName, ComputerName)
- Event identifiers

### 5. DRAPE Calculation
Applies the DRAPE formula to compute the efficiency score for each detection, then sorts by score (descending) to surface the best and worst performing detections.


### Example Dashboard Metrics
```humio
// Detection Quality Distribution
| groupBy([case { DRAPE < 0 | Quality := "Bad"; DRAPE < 5 | Quality := "Weak"; DRAPE < 15 | Quality := "Decent"; * | Quality := "Strong" }], function=count())

// Top 10 Worst Performers (Candidates for Tuning)
| sort(DRAPE, order=asc, limit=10)

// Top 10 Best Performers (High Value Detections)
| sort(DRAPE, order=desc, limit=10)

// Overall Detection Program Score
| avg(DRAPE, as=AvgDRAPE) | sum(TP, as=TotalTP) | sum(FP, as=TotalFP)
```


### Important Considerations

#### TP/FP Definition Consistency
Ensure your team has a consistent definition of what constitutes a TP vs FP:
- **True Positive**: Detection correctly identified malicious/policy-violating activity
- **False Positive**: Detection fired on benign/authorized activity
- **Edge cases**: Document how to handle ambiguous situations

#### Time Window
- Use a rolling 30-90 day window for stable metrics
- Shorter windows (7-14 days) for rapid iteration during tuning
- Longer windows may mask recent improvements


## Tuning Parameters

### Adjusting w (Precision Reward Weight)
```humio
| w:=3.0  // More aggressive reward for high precision
```
- Increase w to favor detections with excellent TP:FP ratios
- Decrease w to be more forgiving of occasional false positives

### Adjusting k (FP Penalty Weight)
```humio
| k:=1.0  // Stricter penalty for false positives
```
- Increase k when FP reduction is critical (high alert fatigue)
- Decrease k when catching threats is more important than noise

### Finding Your Zero Line
The default parameters set the zero line around 1:90 TP:FP ratio. Adjust based on your environment's tolerance:
```humio
// More aggressive (zero line at ~1:50)
| w:=2.5 | k:=0.8

// More forgiving (zero line at ~1:120)
| w:=1.5 | k:=0.3
```

## Limitations and Challenges

1. **Analyst Consistency**: DRAPE quality depends on consistent TP/FP labeling across analysts
2. **Label Lag**: Detections may not be triaged immediately, creating delay in metrics
3. **Unlabeled Detections**: Not all detections get labeled (especially true positives that are actioned immediately)
4. **Context Loss**: Simple TP/FP binary doesn't capture nuance (e.g., "true positive but expected")
5. **Gaming Risk**: Analysts may avoid labeling to prevent "bad scores" on their detections

## Advanced Enhancements

### Per-Detection Rule Analysis
```humio
| RuleName:=coalesce(DetectName, IOARuleName, Name)
| groupBy([RuleName], function=[sum(TP), sum(FP), count()])
// Then apply DRAPE calculation per rule
```

### Analyst Performance Metrics
```humio
| groupBy([UserId], function=[avg(DRAPE), count()])
// Identify analysts who may need TP/FP training
```

### Trend Analysis
```humio
| bucket(@timestamp, span=1d)
// Calculate daily DRAPE to track improvement over time
```
