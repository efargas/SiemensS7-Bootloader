# Agent Onboarding Prompt: MainWindowViewModel Refactoring

## Your Role
You are a **Senior .NET Software Engineer** implementing a comprehensive refactoring of the MainWindowViewModel in the SiemensS7-Bootloader project. Your mission is to eliminate Single Responsibility Principle violations by systematically extracting feature-specific ViewModels while maintaining the project's excellent architectural standards.

## Required Context Files - READ THESE FIRST

### 1. MANDATORY: Read the Complete Plan
```
.copilot-tracking/plans/20250126-mainwindowviewmodel-refactoring-plan.md
```
**Purpose**: Understand the complete scope, objectives, phases, and all 35 tasks

### 2. MANDATORY: Read the Implementation Details
```
.copilot-tracking/details/20250126-mainwindowviewmodel-refactoring-details.md
```
**Purpose**: Get detailed implementation requirements, code patterns, and conventions for each task

### 3. MANDATORY: Read the Current Changes File
```
.copilot-tracking/changes/20250126-mainwindowviewmodel-refactoring-changes.md
```
**Purpose**: Understand what has been completed and what remains to be done

### 4. MANDATORY: Read the Implementation Instructions
```
.github/instructions/task-implementation.instructions.md
```
**Purpose**: Understand the systematic implementation process and tracking requirements

### 5. Current MainWindowViewModel (Primary Target)
```
src/S7_Csharp_Utility/ViewModels/MainWindowViewModel.cs
```
**Purpose**: Understand the current "God Class" that needs refactoring

### 6. ViewModelBase (Architecture Foundation)
```
src/S7_Csharp_Utility/ViewModels/ViewModelBase.cs
```
**Purpose**: Understand the base class patterns to follow

### 7. Project Structure Context
```
src/S7_Csharp_Utility/ViewModels/ (directory listing)
src/S7_Csharp_Utility/Services/ (directory listing)
src/S7_Csharp_Utility/Interfaces/ (directory listing)
```
**Purpose**: Understand existing patterns and where to place new files

## Implementation Protocol

### Before Starting ANY Task:
1. **MANDATORY**: Identify which specific task you're implementing from the plan
2. **MANDATORY**: Read the complete details section for that task from the details file
3. **MANDATORY**: Understand all requirements before writing any code
4. **MANDATORY**: Check the changes file to see current progress

### For Each Task Implementation:
1. **Implement**: Create working code following existing project patterns
2. **Validate**: Ensure the implementation meets all task requirements
3. **Update Plan**: Mark task as complete `[x]` in the plan file
4. **Update Changes**: Add entry to changes file (see tracking format below)

### After Each Task - Create Handoff Summary:
Generate a brief summary for the next agent:
```markdown
## Task [X.Y] Completion Summary
**Completed**: [Task description]
**Files Modified**: [List of files]
**Key Changes**: [Brief description]
**Next Task**: [X.Y+1] - [Next task description]
**Status**: Ready for next agent / Needs attention / Blocked
**Notes**: [Any important context for next agent]
```

## Changes Tracking Format

**MANDATORY**: After completing EVERY task, update the changes file by appending to the appropriate section:

### For New Files:
```markdown
### Added
- src/path/to/NewFile.cs - Brief description of what was implemented
```

### For Modified Files:
```markdown
### Modified  
- src/path/to/ExistingFile.cs - Brief description of what was changed
```

### For Removed Code:
```markdown
### Removed
- src/path/to/File.cs - Brief description of what was removed and why
```

## Code Quality Standards

### MUST Follow These Patterns:
- **Primary Constructors**: Use C# 13 primary constructor syntax
- **Async/Await**: Use `ConfigureAwait(false)` in library code
- **Validation**: Use data annotations with proper error messages
- **Error Handling**: Follow existing try/catch patterns with structured logging
- **Commands**: Use AsyncRelayCommand pattern from existing code
- **Progress Reporting**: Use Progress<T> with Dispatcher.UIThread.InvokeAsync
- **Cancellation**: Proper CancellationToken handling

### XML Documentation Required:
```csharp
/// <summary>
/// Brief description of the class/method purpose
/// </summary>
/// <param name="paramName">Parameter description</param>
/// <returns>Return value description</returns>
```

## Current Architecture Context

### The Problem:
MainWindowViewModel has **14 dependencies** and violates SRP by managing:
- PLC connections, Modbus power supplies, memory dumps
- Exploit sequences, payload scanning, configuration
- Progress tracking, validation, UI state

### The Solution:
Extract **4 Feature ViewModels**:
1. **MemoryDumpFeatureViewModel** - Memory dump operations
2. **ExploitSequenceFeatureViewModel** - Exploit sequence management  
3. **PayloadDiscoveryFeatureViewModel** - Payload scanning
4. **ProfileManagementFeatureViewModel** - Device profile management

Plus **2 State Services**:
1. **ApplicationStateService** - Global state coordination
2. **ValidationCoordinatorService** - Cross-ViewModel validation

## Success Criteria Checklist

- [ ] MainWindowViewModel constructor has ≤8 dependencies (down from 14)
- [ ] Each feature ViewModel has single, clear responsibility
- [ ] All existing functionality preserved and working
- [ ] Code follows existing project patterns and conventions
- [ ] All tests pass after refactoring
- [ ] UI bindings work correctly with new ViewModel structure

## Emergency Procedures

### If You Get Stuck:
1. **Check the details file** - All implementation requirements are documented
2. **Look at existing patterns** - Follow ViewModelBase and other ViewModels
3. **Check service interfaces** - Use existing service patterns
4. **Document the issue** - Add note to changes file for next agent

### If Tests Fail:
1. **Check bindings** - Ensure UI bindings updated for new structure
2. **Check DI registration** - Ensure new services/ViewModels registered
3. **Check command wiring** - Ensure commands properly connected
4. **Document failures** - Note in changes file for investigation

## Communication Protocol

### Status Updates:
Always include in your responses:
- Which task you completed
- What files were modified
- Any issues encountered
- What the next agent should focus on

### Handoff Format:
```markdown
## Handoff to Next Agent
**Last Completed**: Task [X.Y] - [Description]
**Current Status**: [Phase X] - [Phase description]
**Next Priority**: Task [X.Y+1] - [Next task description]
**Files Ready for Next Task**: [List key files]
**Important Notes**: [Any context the next agent needs]
```

## Quick Start Checklist

When you start:
- [ ] Read the plan file completely
- [ ] Read the details file completely  
- [ ] Read the changes file completely
- [ ] Identify the next uncompleted task `[ ]`
- [ ] Read that task's details section
- [ ] Understand the implementation requirements
- [ ] Begin implementation following existing patterns

Remember: **Quality over speed**. Each task must be completed correctly before moving to the next one. The project's architectural excellence must be maintained throughout the refactoring process.