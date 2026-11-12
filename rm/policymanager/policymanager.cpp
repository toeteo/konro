#include "policymanager.h"
#include "policies/nopolicy.h"
#include "policies/randpolicy.h"
#include "policies/puprogressivepolicy.h"
#include "policies/mincorespolicy.h"
#include "threadname.h"
#include "eventbus.h"
#include <iostream>
#include <sstream>
#include <thread>

using namespace std;

namespace rp {

/*!
 * Compares two AppMapping ("less" function) handled
 * by shared pointers
 *
 * \param lhs the first app to compare
 * \param rhs the second app to compare
 * \return true if pid of lsh is < than pid of rhs
 */
static bool appMappingComp(const AppMappingPtr &lhs, const AppMappingPtr &rhs)
{
    return lhs->getPid() < rhs->getPid();
}

PolicyManager::PolicyManager(rmcommon::EventBus &bus, PlatformDescription pd, Policy policy) :
    rmcommon::BaseEventReceiver("POLICYMANAGER"),
    cat_(log4cpp::Category::getRoot()),
    bus_(bus),
    platformDescription_(pd),
    apps_(appMappingComp)
{
    subscribeToEvents();
    policy_ = makePolicy(policy);
}

std::unique_ptr<IBasePolicy> PolicyManager::makePolicy(Policy policy)
{
    switch (policy) {
    case Policy::RandPolicy:
        return make_unique<RandPolicy>(apps_, platformDescription_);
    case Policy::PuProgressivePolicy:
        return make_unique<PuProgressivePolicy>(apps_, platformDescription_);
    case Policy::MinCoresPolicy:
        return make_unique<MinCoresPolicy>(apps_, platformDescription_);
    case Policy::NoPolicy:
    default:
        return make_unique<NoPolicy>();
        break;
    }
}

PolicyManager::Policy PolicyManager::getPolicyByName(const std::string &policyName)
{
    if (policyName == "RandPolicy")
        return Policy::RandPolicy;
    else if (policyName == "PuProgressivePolicy")
        return Policy::PuProgressivePolicy;
    else if (policyName == "MinCoresPolicy")
        return Policy::MinCoresPolicy;
    else
        return Policy::NoPolicy;
}

void PolicyManager::subscribeToEvents()
{
    using namespace rmcommon;

    bus_.subscribe<PolicyManager, AddEvent, BaseEvent>(this, &PolicyManager::addEvent);
    bus_.subscribe<PolicyManager, RemoveEvent, BaseEvent>(this, &PolicyManager::addEvent);
    bus_.subscribe<PolicyManager, TimerEvent, BaseEvent>(this, &PolicyManager::addEvent);
    bus_.subscribe<PolicyManager, FeedbackEvent, BaseEvent>(this, &PolicyManager::addEvent);
    bus_.subscribe<PolicyManager, MonitorEvent, BaseEvent>(this, &PolicyManager::addEvent);
    bus_.subscribe<PolicyManager, SecurityEvent, BaseEvent>(this, &PolicyManager::addEvent);
}

bool PolicyManager::processEvent(std::shared_ptr<const rmcommon::BaseEvent> event)
{
    using namespace rmcommon;

#if 0
    ostringstream os;
    os << "POLICYMANAGER received message => " << *event;
    cat_.debug(os.str());
#endif
    if (const AddEvent *e = dynamic_cast<const AddEvent *>(event.get())) {
        processAddEvent(static_pointer_cast<const AddEvent>(event));
    } else if (const RemoveEvent *e = dynamic_cast<const RemoveEvent *>(event.get())) {
        processRemoveEvent(static_pointer_cast<const RemoveEvent>(event));
    } else if (const TimerEvent *e = dynamic_cast<const TimerEvent *>(event.get())) {
        processTimerEvent(static_pointer_cast<const TimerEvent>(event));
    } else if (const MonitorEvent *e = dynamic_cast<const MonitorEvent *>(event.get())) {
        processMonitorEvent(static_pointer_cast<const MonitorEvent>(event));
    } else if (const FeedbackEvent *e = dynamic_cast<const FeedbackEvent *>(event.get())) {
        processFeedbackEvent(static_pointer_cast<const FeedbackEvent>(event));
    } else if (const SecurityEvent *e = dynamic_cast<const SecurityEvent *>(event.get())) {
        processSecurityEvent(static_pointer_cast<const SecurityEvent>(event));
    }
    return true;        // continue processing
}

void PolicyManager::processAddEvent(std::shared_ptr<const rmcommon::AddEvent> event)
{
    cat_.debug("POLICYMANAGER AddEvent received");
    AppMappingPtr appMapping = make_shared<AppMapping>(event->getApp());
    apps_.insert(appMapping);
    indexApp(appMapping);
    dumpApps();
    policy_->addApp(appMapping);
}

void PolicyManager::indexApp(const AppMappingPtr &appMapping)
{
    const std::shared_ptr<rmcommon::App> &app = appMapping->getApp();
    pid_t pid = app->getPid();
    if (!app->getNode().empty()) {
        nodeMap_[app->getNode()].insert(pid);
    }
    for (const std::string &source: app->getSources()) {
        sourceMap_[source].insert(pid);
    }
}

void PolicyManager::unindexApp(const AppMappingPtr &appMapping)
{
    const std::shared_ptr<rmcommon::App> &app = appMapping->getApp();
    pid_t pid = app->getPid();
    // Only this PID is erased: a new instance of the same task (e.g. after a
    // migration) has another PID and its entries are not affected, even if its
    // AddEvent was received before the RemoveEvent of the old one.
    auto erasePid = [pid](std::map<std::string, PidSet> &map, const std::string &key) {
        auto it = map.find(key);
        if (it != map.end()) {
            it->second.erase(pid);
            if (it->second.empty()) {
                map.erase(it);
            }
        }
    };
    erasePid(nodeMap_, app->getNode());
    for (const std::string &source: app->getSources()) {
        erasePid(sourceMap_, source);
    }
}

AppMappingPtr PolicyManager::findAppByPid(pid_t pid) const
{
    AppMappingPtr key = make_shared<AppMapping>(rmcommon::App::makeApp(pid, rmcommon::App::AppType::UNKNOWN));
    auto it = apps_.find(key);
    return it != end(apps_) ? *it : nullptr;
}

std::vector<AppMappingPtr> PolicyManager::appsOnNode(const std::string &node) const
{
    std::vector<AppMappingPtr> res;
    auto it = nodeMap_.find(node);
    if (it != nodeMap_.end()) {
        for (pid_t pid: it->second) {
            if (AppMappingPtr am = findAppByPid(pid)) {
                res.push_back(am);
            }
        }
    }
    return res;
}

std::vector<AppMappingPtr> PolicyManager::appsFedBy(const std::string &source) const
{
    std::vector<AppMappingPtr> res;
    auto it = sourceMap_.find(source);
    if (it != sourceMap_.end()) {
        for (pid_t pid: it->second) {
            if (AppMappingPtr am = findAppByPid(pid)) {
                res.push_back(am);
            }
        }
    }
    return res;
}

void PolicyManager::processSecurityEvent(std::shared_ptr<const rmcommon::SecurityEvent> event)
{
    ostringstream os;
    os << "POLICYMANAGER SecurityEvent received => " << *event;
    cat_.info(os.str());
    
    const std::string &node = event->getName();
    if (node.empty()) {
        cat_.warn("POLICYMANAGER SecurityEvent without node name, ignored");
        return;
    }
    compromisedNodes_.insert(node);

    for (const AppMappingPtr &am: appsOnNode(node)) {
        cat_.info("POLICYMANAGER node %s is compromised: task \"%s\" (pid %ld) runs on it",
                  node.c_str(), am->getApp()->getName().c_str(), (long)am->getPid());
    }
    for (const AppMappingPtr &am: appsFedBy(node)) {
        cat_.info("POLICYMANAGER node %s is compromised: task \"%s\" (pid %ld) reads data from it",
                  node.c_str(), am->getApp()->getName().c_str(), (long)am->getPid());
    }
}

void PolicyManager::processRemoveEvent(std::shared_ptr<const rmcommon::RemoveEvent> event)
{
    cat_.debug("POLICYMANAGER RemoveProc event received");
    // search target
    AppMappingPtr appMapping = make_shared<AppMapping>(event->getApp());
    auto it = apps_.find(appMapping);
    if (it != end(apps_)) {
        policy_->removeApp(*it);
        unindexApp(*it);
        apps_.erase(it);
    }
    dumpApps();
}

void PolicyManager::processTimerEvent(std::shared_ptr<const rmcommon::TimerEvent> event)
{
    cat_.debug("POLICYMANAGER timer event received");
    policy_->timer();
}

void PolicyManager::processMonitorEvent(std::shared_ptr<const rmcommon::MonitorEvent> event)
{
    ostringstream os;
    os << "POLICYMANAGER monitor event received => " << *event;
    cat_.info(os.str());
    policy_->monitor(event);
}

void PolicyManager::processFeedbackEvent(std::shared_ptr<const rmcommon::FeedbackEvent> event)
{
    using namespace rmcommon;

    KonroTimer::TimeUnit micros = KonroTimer::ElapsedFrom(event->getTimePoint());
    cat_.debug("POLICYMANAGER feedback event received for pid %d, delivered in %ld microseconds",
               event->getApp()->getPid(),
               (long)micros.count());

    AppMappingPtr appMapping = make_shared<AppMapping>(event->getApp());
    auto it = apps_.find(appMapping);
    if (it != end(apps_)) {
        policy_->feedback(*it, event->getFeedback());
    } else {
        cat_.error("POLICYMANAGER feedback event: AppMapping not found for pid %d",
                   event->getApp()->getPid());
    }
}

void PolicyManager::dumpApps() const
{
    std::ostringstream os;
    os << "POLICYMANAGER handling PIDS [";
    bool first = true;
    for (auto &app: apps_) {
        if (first)
            first = false;
        else
            os << ",";
        os << app->getPid();
    }
    os << "]";
    cat_.info(os.str());
}

}   // namespace rp
