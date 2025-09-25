# AI Coding Agent Instructions (Repository: SiemensS7-Bootloader)

## 🎯 **CURRENT PROJECT STATUS** (Updated: 2025-01-24)

### ✅ **COMPLETED PHASES**
- **Phase 1**: Project Foundation ✅ COMPLETE (100%)
- **Phase 2 - Task 2.1**: Repository Pattern Implementation ✅ COMPLETE (100%)
- **Phase 2 - Task 2.2**: Factory Pattern Enhancement ✅ COMPLETE (100%)

### 🔄 **NEXT PRIORITY TASK**
**Task 2.3**: Provider Pattern Completion
- **Status**: Ready to begin
- **Priority**: HIGH
- **Estimated Time**: 4-6 hours
- **Tracking**: `.copilot-tracking/changes/20250124-phase2-task3-provider-pattern.md`

### 📊 **BUILD STATUS**
- **Current**: ✅ SUCCESS (0 errors, 35 acceptable warnings)
- **Quality**: 🟢 EXCELLENT
- **Architecture**: Modern DI-based patterns implemented

---

## 📋 **PURPOSE & SCOPE**

Agents assist contributors by producing code, tests, docs, and change-tracking artifacts following the repo conventions below. This project implements a modern C# bootloader utility with clean architecture patterns.

**Key Technologies**: .NET 8, Avalonia UI, Microsoft.Extensions.DependencyInjection, Repository Pattern, Factory Pattern, Provider Pattern

---

## 🛠️ **GENERAL RULES**

### **Code Quality Standards**
- Always follow this repository's branching, PR, and tracking conventions
- Only modify files under `src/`, `docs/`, `scripts/`, `.copilot-tracking/`, `agents/workspace/` and `reports/` unless instructed otherwise
- Never delete existing tests or change production code behavior without adding tests
- Every code change must include at least one unit test or updated integration test
- When moving files between projects, create adapters in the old location with `[Obsolete]` and keep them for one release

### **Architecture Compliance**
- Follow SOLID principles and established patterns (Repository, Factory, Provider)
- Use dependency injection throughout (`Microsoft.Extensions.DependencyInjection`)
- Maintain backward compatibility with legacy components
- Implement proper async/await patterns with `ConfigureAwait(false)`
- Provide 100% XML documentation for public APIs

---

## 🌿 **BRANCHING AND COMMITS**

### **Branch Naming**
- Feature branches: `feature/<short>-<desc>` (e.g., `feature/provider-pattern`)
- Chore branches: `chore/<desc>` (e.g., `chore/update-docs`)

### **Commit Standards**
- Write small commits (<200 LOC) with meaningful messages
- Use scope prefixes: `core:`, `ui:`, `services:`, `infrastructure:`, `tests:`
- Add plan reference: `"core: add IProviderFactory (plan: .copilot-tracking/changes/20250124-phase2-task3-provider-pattern.md)"`

### **Examples**
```
core: implement IServiceProvider integration
infrastructure: add provider factory with DI support
tests: add unit tests for provider pattern
docs: update provider pattern documentation
```

---

## 📊 **PROGRESS TRACKING**

### **Implementation Tracking**
- Progress tracked in `.copilot-tracking/plans/` and `.copilot-tracking/changes/`
- For each completed task:
  - Update plan file (change `[ ]` -> `[x]`)
  - Append entry to relevant `.copilot-tracking/changes/YYYYMMDD-*.md` file
  - Include Added/Modified/Removed entries with file paths

### **Current Tracking Files**
- **Active**: `.copilot-tracking/changes/20250124-phase2-task3-provider-pattern.md` (Next task)
- **Completed**: `.copilot-tracking/changes/20250124-phase2-task2-factory-pattern.md` ✅
- **Completed**: `.copilot-tracking/changes/20250124-phase2-task1-repository-pattern.md` ✅

---

## 🔄 **PR AND MERGE RULES**

### **PR Preparation**
- Use `.github/PULL_REQUEST_TEMPLATE.md` for PR descriptions
- Include: summary, related plan path, acceptance checklist, tests added, migration notes
- **DO NOT MERGE** - Open PR for human reviewers only

### **PR Content Requirements**
- Build validation: `dotnet build src/SiemensS7-Bootloader.sln` passes
- Test validation: All existing tests continue to pass
- Documentation: XML docs for new public APIs
- Backward compatibility: No breaking changes to existing APIs

---

## 🎨 **CODE STYLE AND CI**

### **Style Guidelines**
- Follow `.editorconfig` settings
- Naming conventions: `IVirtualFileReader`, `ReadOnlyMemory<byte>`, `Async` suffix
- Use `ConfigureAwait(false)` for all async calls in libraries
- Implement proper disposal patterns for `IDisposable`

### **CI Requirements**
- All changes must pass `dotnet build` and `dotnet test`
- No new compilation errors (warnings are acceptable if documented)
- Maintain or improve test coverage
- Follow established project structure

---

## 📁 **FILE ORGANIZATION**

### **Agent Workspace**
- Agents work inside `agents/workspace/`
- Produce patches, PR drafts, and implementation plans
- Generate step-by-step instructions and suggested git commands

### **Project Structure**
```
src/
├── S7_Csharp_Core/           # Core business logic
│   ├── S7.Core.Abstractions/ # Interfaces and contracts
│   ├── S7.Infrastructure/    # Repository and factory implementations
│   ├── S7.Services/          # Service layer with DI
���   └── S7.Core.Commands/     # Command handlers and extensions
├── S7_Csharp_Utility/        # Avalonia UI application
tests/                        # Unit and integration tests
.copilot-tracking/           # Progress tracking and plans
```

---

## 🔒 **SECURITY AND SAFETY**

### **Restricted Areas**
- **DO NOT** create or modify files under `tools/`, `firmware/`, or payload locations without explicit human approval
- For hardware integration code, ensure tests are mocks or synthetic only
- Never run hardware commands in CI environment

### **Safe Development**
- All hardware interactions must be abstracted behind interfaces
- Use dependency injection for testability
- Implement proper error handling and validation
- Follow principle of least privilege

---

## 🚀 **NEXT STEPS FOR AGENTS**

### **Immediate Priority: Task 2.3 - Provider Pattern**
1. **Read Current Status**: Review `.copilot-tracking/changes/20250124-phase2-task2-factory-pattern.md`
2. **Create Tracking Document**: Initialize `.copilot-tracking/changes/20250124-phase2-task3-provider-pattern.md`
3. **Implement Provider Pattern**: 
   - Create `IServiceProvider` integration
   - Add provider factory with configuration support
   - Implement service discovery mechanisms
   - Add comprehensive unit tests
4. **Validate Implementation**: Ensure build passes and tests succeed
5. **Update Documentation**: XML docs and implementation notes

### **Success Criteria**
- ✅ Build passes: `dotnet build src/SiemensS7-Bootloader.sln`
- ✅ Tests pass: `dotnet test`
- ✅ No breaking changes to existing APIs
- ✅ 100% XML documentation for new public APIs
- ✅ Proper DI integration following established patterns

### **Quality Standards**
- Maintain 100% success rate established in previous phases
- Follow SOLID principles and clean architecture
- Implement comprehensive error handling
- Provide backward compatibility where needed

---

## 📚 **ESTABLISHED PATTERNS TO FOLLOW**

### **Repository Pattern** (Completed ✅)
- Generic `IRepository<T>` interfaces with full CRUD operations
- Unit of Work pattern with transaction management
- Specialized repositories: `IFileRepository`, `IMemoryDumpRepository`
- Complete implementations with caching and performance optimization

### **Factory Pattern** (Completed ✅)
- DI-based factory creation with `Microsoft.Extensions.DependencyInjection`
- Configuration-driven factory selection
- Abstract factory pattern for families of related objects
- Service registration extensions with lifetime management
- Backward compatibility with legacy static factories

### **Provider Pattern** (Next Task 🔄)
- Service provider integration with DI container
- Provider discovery and registration mechanisms
- Configuration-based provider selection
- Pluggable provider implementations
- Provider lifetime management and scoping

---

## 🏗️ **ARCHITECTURE OVERVIEW**

### **Current Implementation Status**
```
✅ S7.Core.Abstractions/     # Interfaces and contracts
   ├── Repositories/         # Repository interfaces
   ├── Factories/           # Factory interfaces  
   ├── Configuration/       # Configuration models
   └── Services/            # Service contracts

✅ S7.Infrastructure/        # Implementation layer
   ├── Repositories/        # Repository implementations
   ├── Factories/          # Factory implementations
   └── [Next: Providers/]   # Provider implementations

✅ S7.Services/             # Service layer
   ├── Interfaces/         # Service interfaces
   ├── Configuration/      # Service configuration
   └── [Enhanced factories] # DI-based factories

✅ S7.Core.Commands/        # Command layer
   ├── Extensions/         # DI registration extensions
   ├── Handlers/          # Command handlers
   └── Services/          # Command services
```

### **DI Container Integration**
- Full `Microsoft.Extensions.DependencyInjection` support
- Configuration binding with `Microsoft.Extensions.Configuration`
- Options pattern with `Microsoft.Extensions.Options`
- Service registration extensions for easy setup
- Lifetime management (Singleton, Scoped, Transient)

---

## 🧪 **TESTING STRATEGY**

### **Test Coverage Requirements**
- Unit tests for all new public APIs
- Integration tests for DI container registration
- Mock-based testing for external dependencies
- Performance tests for critical paths
- Backward compatibility tests

### **Test Organization**
```
tests/
├── S7.Core.Tests/           # Core logic tests
├── S7_Csharp_Utility.Tests/ # UI tests
└── [Integration tests]      # Cross-component tests
```

---

## 📖 **DOCUMENTATION STANDARDS**

### **XML Documentation**
- 100% coverage for public APIs
- Include `<summary>`, `<param>`, `<returns>`, `<exception>`
- Provide usage examples for complex APIs
- Document thread safety and async behavior

### **Implementation Notes**
- Update tracking documents with technical decisions
- Document breaking changes and migration paths
- Include performance considerations
- Provide troubleshooting guidance

---

**Last Updated**: 2025-01-24  
**Project Health**: 🟢 EXCELLENT  
**Ready for**: Task 2.3 - Provider Pattern Completion  
**Success Rate**: 100% (maintained across all completed phases)