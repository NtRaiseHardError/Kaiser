Get-WmiObject __EventFilter -Namespace root\subscription -Filter "Name='KaiserFilter'" | Remove-WmiObject
Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription -Filter "Filter=""__EventFilter.Name='KaiserFilter'""" | Remove-WmiObject
Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -Filter "Name='KaiserConsumer'" | Remove-WmiObject